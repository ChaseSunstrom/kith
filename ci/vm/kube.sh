# shellcheck shell=sh
# shellcheck disable=SC2154 # (names the driver and its parts share)
# shellcheck disable=SC2015 # (as the script had them before it was cut)
# Sourced by ci/vm.sh for --test kube: it runs inside the driver's shell, with its
# variables and functions; not a script to run alone.
            # kubectl and helm as they are shipped, on this machine, asking the first node as
            # the cluster's admin: what they are given has nothing of kith in it but an
            # image's name. (What they keep for themselves stays in the test's directory.)
            cat >"$work/kubeconfig" <<EOF
apiVersion: v1
kind: Config
current-context: kith
clusters:
- name: kith
  cluster: { server: "https://127.0.0.1:$((port + 1))", certificate-authority: ca.pem, tls-server-name: kith }
users:
- name: root
  user: { client-certificate: cert.pem, client-key: key.pem }
contexts:
- name: kith
  context: { cluster: kith, user: root }
EOF
            mkdir "$work/home"
            k() { HOME="$work/home" KUBECONFIG="$work/kubeconfig" "$kubectl" "$@"; }
            must() { # WHAT IT IS, and a command that has to succeed (what it said: $work/said)
                what=$1
                shift
                "$@" >"$work/said" 2>&1 || fail "$what: $(cat "$work/said"): $(k get pods,jobs,pvc -o wide 2>&1)"
            }
            # NAME and what must be in it: wait for that Job to complete, and read what its
            # pod heard (kubectl logs), which is in $work/NAME.out.
            heard() {
                job=$1
                shift
                must "the Job $job did not complete" k wait --for=condition=complete "job/$job" --timeout=240s
                k logs "job/$job" >"$work/$job.out" 2>"$work/said" || fail "kubectl logs job/$job: $(cat "$work/said")"
                ! grep -q 'failed: ' "$work/$job.out" || fail "the Job $job was not always answered: $(cat "$work/$job.out")"
                for line in "$@"; do
                    grep -q "$line" "$work/$job.out" || fail "the Job $job did not hear \"$line\": $(cat "$work/$job.out")"
                done
            }

            # The manifests: a Deployment told things by a ConfigMap and a Secret, behind a
            # Service with an Ingress, and a StatefulSet with a claim nobody made a volume for.
            waited=0
            until k get node n2 >/dev/null 2>&1; do
                waited=$((waited + 1))
                [ "$waited" -lt 120 ] || fail "kubectl sees no second node: $(k get nodes 2>&1)"
                sleep 1
            done
            must 'the two nodes are not both ready' k wait --for=condition=Ready node/n1 node/n2 --timeout=120s
            must 'kubectl apply of the shop and the db' k apply -f "$root/ci/kube/shop.yaml" -f "$root/ci/kube/db.yaml"
            must 'the Deployment did not roll out' k rollout status deployment/shop --timeout=240s
            must 'the StatefulSet did not roll out' k rollout status statefulset/db --timeout=240s
            k get pods -o wide >"$work/pods" 2>&1 || fail "kubectl get pods: $(cat "$work/pods")"
            [ "$(grep -c ' Running ' "$work/pods")" = 4 ] || fail "not four pods running: $(cat "$work/pods")"
            [ "$(k get pvc data-db-0 -o 'jsonpath={.status.phase}')" = Bound ] || fail "the StatefulSet's claim is not bound: $(k get pvc 2>&1)"
            k get ingress shop 2>&1 | grep -q shop.example.com || fail "the Ingress does not say its host: $(k get ingress 2>&1)"
            must 'kubectl logs of a running pod' k logs shop-0
            must 'kubectl describe of a running pod' k describe pod shop-0
            # The ways into a running pod are not here, and say so.
            if timeout 60 env HOME="$work/home" KUBECONFIG="$work/kubeconfig" "$kubectl" port-forward shop-0 "$((port + 10)):80" >"$work/said" 2>&1; then
                fail "kubectl port-forward was answered"
            fi
            grep -q 'not answered here' "$work/said" || fail "kubectl port-forward was not refused in words: $(cat "$work/said")"

            # A Job, and a CronJob's Job made by the clock: each hears the three of the shop,
            # what they were told, and the db, which has started once.
            must 'kubectl apply of the Job and the CronJob' k apply -f "$root/ci/kube/jobs.yaml"
            heard ask 'shop-0 hello hunter2' 'shop-1 hello hunter2' 'shop-2 hello hunter2' 'db-0 started 1'
            # The replica's own name and the headless Service's name answer an address each
            # (AAAA: a client that asks for IPv6, which getaddrinfo does; the Service's name
            # answers its IPv4 address too, so its list has both); the pod says so, a line a name. Anchored, so each line is its own name's: with one replica the
            # headless answer is db-0's address, and not the db Service's.
            heard replicas '^db-0.db-replicas.default.svc.cluster.local: \["[0-9a-f]*:' '^db-replicas.default.svc.cluster.local: \["[0-9a-f]*:' '^db.default.svc.cluster.local: \[.*"[0-9a-f]*:[0-9a-f:]*"'
            own=$(sed -n 's/^db-0\.db-replicas\.default\.svc\.cluster\.local: //p' "$work/replicas.out")
            headless=$(sed -n 's/^db-replicas\.default\.svc\.cluster\.local: //p' "$work/replicas.out")
            svc=$(sed -n 's/^db\.default\.svc\.cluster\.local: //p' "$work/replicas.out")
            [ -n "$own" ] && [ "$headless" = "$own" ] && [ -n "$svc" ] && [ "$svc" != "$own" ] || fail "the headless name does not answer db-0's address, or the db Service's is its own: $(cat "$work/replicas.out")"
            waited=0
            until tick=$(k get jobs -o name 2>/dev/null | grep -m 1 '^job.batch/tick-'); do
                waited=$((waited + 1))
                [ "$waited" -lt 100 ] || fail "the CronJob made no Job in a minute and a half: $(k get cronjobs,jobs 2>&1)"
                sleep 1
            done
            heard "${tick#job.batch/}" 'shop-0 hello hunter2' 'db-0 started 1'
            # Restarted, the db is a new pod with the file the old one wrote: a Job made
            # from the CronJob by hand hears that it has started twice.
            must 'kubectl rollout restart' k rollout restart statefulset/db
            must 'the StatefulSet did not roll out again' k rollout status statefulset/db --timeout=240s
            must 'kubectl create job --from' k create job again --from=cronjob/tick
            heard again 'db-0 started 2'

            # The Service's IPv4 address (--service-range): a client reaches a Service by the
            # A record its resolver at the pod range's IPv4 gateway answers with, and by that
            # address as a literal (which a fallback to IPv6 cannot do). (The replica's peer is
            # kithd's own connection on the pod's loopback, whose family kithd picks: not asserted.) (A pod cannot turn IPv6 off in its own
            # namespace, its /proc/sys is read-only: the pod says whether it did, and a
            # namespace with it off is proved in kith-mesh's pod tests.) The replicas are
            # on both nodes, so with the client on one, the Service's connections reach one on
            # its own node and one on the other. A client with IPv6 is still given the AAAA.
            must 'kubectl apply of the Service with an IPv4 address' k apply -f "$root/ci/kube/v4.yaml"
            must 'the Deployment behind the IPv4 Service did not roll out' k rollout status deployment/echo4 --timeout=240s
            must 'kubectl apply of the clients of the IPv4 Service' k apply -f "$root/ci/kube/v4clients.yaml"
            heard v4only '^ipv6: ' '^addresses: \[100\.87\.[0-9]*\.[0-9]*\]' 'name: HTTP/1.0 200 OK echo4-[0-9] peer[46] ' 'literal: HTTP/1.0 200 OK echo4-[0-9] peer[46] '
            ! grep -q 'failed' "$work/v4only.out" || fail "a connection to the IPv4 Service failed: $(cat "$work/v4only.out")"
            must 'kubectl create job, to look the IPv4 Service up with IPv6 on' k create job both --image=kith.test/pod:1 -- /bin/pod lookup echo4.default.svc.cluster.local
            heard both '^echo4.default.svc.cluster.local: \[.*"100\.87\.[0-9.]*"' '^echo4.default.svc.cluster.local: \[.*"[0-9a-f]*:[0-9a-f:]*"'
            k get pods -o 'jsonpath={range .items[*]}{.metadata.name} {.spec.nodeName}{"\n"}{end}' >"$work/where" 2>&1 || fail "kubectl get pods: $(cat "$work/where")"
            client=$(sed -n 's/^v4only[^ ]* //p' "$work/where")
            [ -n "$client" ] || fail "the client's node is not said: $(cat "$work/where")"
            grep "^echo4-[0-9] $client\$" "$work/where" >/dev/null || fail "no replica on the client's node $client: $(cat "$work/where")"
            grep "^echo4-[0-9] " "$work/where" | grep -v " $client\$" >/dev/null || fail "no replica on the other node than $client: $(cat "$work/where")"
            for replica in $(sed -n 's/^\(echo4-[0-9]\) .*/\1/p' "$work/where"); do
                grep -q "name: HTTP/1.0 200 OK $replica peer[46] " "$work/v4only.out" || fail "the client's connections by name never reached $replica: $(cat "$work/v4only.out") on $(cat "$work/where")"
            done
            must 'kubectl delete of the Service with an IPv4 address' k delete deployment/echo4 service/echo4 job/v4only job/both

            # What a stock chart says of a pod beyond its image (ci/kube/files.yaml): a
            # ConfigMap and a Secret as files, directories of its own, what it is told from
            # maps and from itself, a user who is not root with no capability, and a
            # container that runs first. The pod says what it finds (ci/pod.rs, tell).
            must 'kubectl apply of the pod with files' k apply -f "$root/ci/kube/files.yaml"
            must 'the Deployment with files did not roll out' k rollout status deployment/files --timeout=240s
            waited=0
            until k logs files-0 -c tell >"$work/files.out" 2>"$work/said" && grep -q '^tell: watching' "$work/files.out"; do
                waited=$((waited + 1))
                [ "$waited" -lt 60 ] || fail "the pod with files has not said what it found: $(cat "$work/said" "$work/files.out")"
                sleep 1
            done
            # (What it found when it started: before it watched for what changes.)
            sed '/^tell: watching/q' "$work/files.out" >"$work/files.first"
            for line in \
                '^tell: started uid 1000 caps eff 0000000000000000 bnd 0000000000000000$' \
                '^tell: env COLOUR=green$' '^tell: env S_token=sesame$' \
                '^tell: env POD_NAME=files-0$' '^tell: env POD_NAMESPACE=default$' '^tell: env NODE_NAME=n[12]$' \
                "^tell: env POD_IP=$(k get pod files-0 -o 'jsonpath={.status.podIP}' | sed 's/\./\\./g')\$" \
                '^tell: mount /etc/conf [^ ]+ /[^ ]+ ro write Err' \
                '^tell: mount /etc/one.conf [^ ]+ /[^ ]+ ro write Err' \
                '^tell: mount /etc/secret tmpfs /kith/replicas/[^ ]+ ro write Err' \
                '^tell: mount /work [^ ]+ /[^ ]+ rw write Ok' \
                '^tell: mount /fast tmpfs /kith/replicas/[^ ]+ rw write Ok' \
                '^tell: file /etc/conf/motd [0-7]+ one$' '^tell: file /etc/conf/site.conf [0-7]+ listen 80$' \
                '^tell: file /etc/one.conf [0-7]+ listen 80$' \
                '^tell: file /etc/secret/creds/token 400 sesame$' \
                '^tell: file /work/first [0-7]+ ran first$'; do
                grep -Eq "$line" "$work/files.first" || fail "the pod with files did not say \"$line\" when it started: $(cat "$work/files.out")"
            done
            [ "$(grep -c '^tell: file /etc/secret/' "$work/files.first")" = 1 ] || fail "the Secret's files are not the one its items name: $(cat "$work/files.out")"
            must 'kubectl logs of the container that ran first' k logs files-0 -c first
            grep -q '^put: /work/first' "$work/said" || fail "the container that ran first did not say so: $(cat "$work/said")"
            said=$(k get pod files-0 -o 'jsonpath={.status.initContainerStatuses[0].state.terminated.reason} {.status.containerStatuses[*].name}' 2>&1)
            [ "$said" = 'Completed tell' ] || fail "the pod with files says of its containers: $said"
            # The ConfigMap changed, its files are the new ones in the pod that was running.
            sed -n '/^kind: ConfigMap/,/^---/p' "$root/ci/kube/files.yaml" | sed -e '/^---/,$d' -e 's/motd: one/motd: two/' >"$work/files-config.yaml"
            { echo 'apiVersion: v1'; cat "$work/files-config.yaml"; } >"$work/files-changed.yaml"
            grep -q 'motd: two' "$work/files-changed.yaml" || fail "the test's changed ConfigMap is not one: $(cat "$work/files-changed.yaml")"
            must 'kubectl apply of the changed ConfigMap' k apply -f "$work/files-changed.yaml"
            waited=0
            until k logs files-0 -c tell 2>&1 | grep -Eq '^tell: file /etc/conf/motd [0-7]+ two$'; do
                waited=$((waited + 1))
                [ "$waited" -lt 60 ] || fail "the changed ConfigMap's file did not change in the pod: $(k logs files-0 -c tell 2>&1)"
                sleep 1
            done
            said=$(k logs files-0 -c tell 2>&1 | grep -c '^tell: started') restarts=$(k get pod files-0 -o 'jsonpath={.status.containerStatuses[0].restartCount}')
            [ "$said $restarts" = '1 0' ] || fail "the pod was started again for a changed file (started $said times, $restarts restarts)"
            # Root without two capabilities has the others, and not those two (13 and 27; CHOWN is 0).
            heard caps '^tell: started uid 0 '
            bnd=$(sed -n 's/^tell: started uid 0 caps eff \([0-9a-f]*\) bnd \1$/\1/p' "$work/caps.out")
            [ -n "$bnd" ] && [ "$((0x$bnd >> 13 & 1))$((0x$bnd >> 27 & 1))$((0x$bnd & 1))" = 001 ] || fail "root without NET_RAW and MKNOD has: $(cat "$work/caps.out")"
            # Told not to be root, an image that names no user does not start, and says why.
            waited=0
            until k get pod rooted-0 -o 'jsonpath={.status.containerStatuses[0].state.waiting.message}' 2>&1 | grep -q runAsNonRoot; do
                waited=$((waited + 1))
                [ "$waited" -lt 60 ] || fail "a pod that would be root under runAsNonRoot does not say so: $(k get pod rooted-0 -o yaml 2>&1)"
                sleep 1
            done
            [ "$(k get pod rooted-0 -o 'jsonpath={.status.phase}')" = Pending ] || fail "a pod that would be root under runAsNonRoot is not pending: $(k get pods 2>&1)"

            # Without a file: made, shown to others, grown and given another image by hand.
            must 'kubectl create deployment' k create deployment made --image=kith.test/pod:serve --replicas=2 --port=80
            must 'kubectl expose' k expose deployment made --port=80
            must 'the Deployment made by hand did not roll out' k rollout status deployment/made --timeout=240s
            must 'kubectl scale' k scale deployment/made --replicas=3
            must 'kubectl set image' k set image deployment/made pod=kith.test/pod:again
            must 'the Deployment made by hand did not roll out again' k rollout status deployment/made --timeout=240s
            said=$(k get deployment made -o 'jsonpath={.status.readyReplicas} {.spec.template.spec.containers[0].image}' 2>&1)
            [ "$said" = '3 kith.test/pod:again' ] || fail "the Deployment made by hand says: $said"
            must 'kubectl create job' k create job ask-made --image=kith.test/pod:1 -- /bin/pod ask made 80
            heard ask-made made-0 made-1 made-2

            # Helm, 3 and 4: the chart it starts every chart from, waited for until it is ready.
            n=0
            for helm in $helms; do
                n=$((n + 1))
                h() { HOME="$work/home" KUBECONFIG="$work/kubeconfig" "$helm" "$@"; }
                must "helm create ($n)" h create "$work/site$n"
                must "helm install --wait ($n)" h install "site$n" "$work/site$n" --set image.repository=kith.test/pod --set image.tag=serve --wait --timeout 240s
                must "helm upgrade --wait ($n)" h upgrade "site$n" "$work/site$n" --reuse-values --set replicaCount=2 --wait --timeout 240s
                [ "$(k get deployment "site$n" -o 'jsonpath={.status.readyReplicas}')" = 2 ] || fail "helm upgrade --wait ($n) came back before two were ready: $(k get deployments 2>&1)"
                h list 2>&1 | grep -q "site$n.*deployed" || fail "helm list ($n) does not say deployed: $(h list 2>&1)"
                must "helm uninstall --wait ($n)" h uninstall "site$n" --wait --timeout 120s
            done

            stock='no stock image was tried (KITH_E2E=1 pulls one)'
            if [ "${KITH_E2E:-}" = 1 ]; then
                # nginx as it is shipped, by hand and as Helm's chart with nothing changed
                # but where the image comes from.
                must 'kubectl create deployment of nginx' k create deployment stock --image=mirror.gcr.io/library/nginx:1.27-alpine --replicas=2 --port=80
                must 'kubectl expose of nginx' k expose deployment stock --port=80
                must 'nginx did not roll out' k rollout status deployment/stock --timeout=480s
                must 'kubectl create job, to ask nginx' k create job ask-stock --image=kith.test/pod:1 -- /bin/pod ask stock 80
                heard ask-stock 'HTTP/1.1 200 OK'
                if [ -n "$helms" ]; then
                    helm=${helms%% *}
                    must 'helm install --wait of nginx' h install stock-site "$work/site1" --set image.repository=mirror.gcr.io/library/nginx --set image.tag=1.27-alpine --wait --timeout 480s
                    must 'helm uninstall of nginx' h uninstall stock-site --wait --timeout 120s
                fi
                must 'kubectl delete of nginx' k delete deployment,service stock
                must 'kubectl delete of the Job that asked nginx' k delete job ask-stock
                stock='nginx as it is shipped (mirror.gcr.io/library/nginx:1.27-alpine) rolled out by kubectl create deployment and by helm install --wait, and answered through its Service'
            fi

            # A StatefulSet of three with a claim template: a claim and a volume for each replica,
            # across the two nodes, each replica on the node of its own volume (also when it
            # starts again), and a claim deleted takes nothing from a replica that is running.
            must 'kubectl apply of the StatefulSet of three' k apply -f "$root/ci/kube/ring.yaml"
            must 'the StatefulSet of three did not roll out' k rollout status statefulset/ring --timeout=240s
            for n in 0 1 2; do
                [ "$(k get pvc "data-ring-$n" -o 'jsonpath={.status.phase}' 2>&1)" = Bound ] || fail "the claim data-ring-$n is not bound: $(k get pvc 2>&1)"
            done
            ring_nodes() { for n in 0 1 2; do k get pod "ring-$n" -o 'jsonpath={.spec.nodeName}' 2>&1; echo; done; }
            ringed=$(ring_nodes)
            [ "$(echo "$ringed" | sort -u | wc -l)" -ge 2 ] || fail "the three replicas are all on one node, not across the two: $ringed"
            must 'kubectl rollout restart of the StatefulSet of three' k rollout restart statefulset/ring
            must 'the StatefulSet of three did not roll out again' k rollout status statefulset/ring --timeout=240s
            [ "$(ring_nodes)" = "$ringed" ] || fail "a replica came back on another node than its volume's: before $ringed, after $(ring_nodes)"
            must 'kubectl delete of one replica'"'"'s claim' k delete pvc data-ring-1
            [ "$(k get pod ring-1 -o 'jsonpath={.status.phase}' 2>&1)" = Running ] || fail "the replica whose claim was deleted stopped: $(k get pods 2>&1)"

            # Deleted, nothing of it is left: not the volume made for the claim either.
            must 'kubectl delete of the manifests' k delete --ignore-not-found -f "$root/ci/kube"
            must 'kubectl delete of what was made by hand' k delete deployment,service made
            must 'kubectl delete of the Jobs made by hand' k delete job again ask-made
            must 'kubectl delete of the claims' k delete pvc data-db-0 data-ring-0 data-ring-2
            left() {
                k get all,pvc,configmaps,secrets,ingress -o name 2>&1
                any GET /v1/resources 2>/dev/null | python3 -c '
import json, sys
found = json.load(sys.stdin)
found = found if isinstance(found, list) else found.get("resources", found.get("items", []))
ours = ("Workload", "Job", "CronJob", "Service", "Volume", "VolumeClaim", "ConfigMap", "Secret", "KubeObject")
for r in found:
    if r["kind"] in ours and r["metadata"].get("namespace") != "kith-system":
        print(r["kind"], r["metadata"]["name"])
'
            }
            waited=0
            until [ -z "$(left)" ]; do
                waited=$((waited + 1))
                [ "$waited" -lt 120 ] || fail "deleted, this is left: $(left)"
                sleep 1
            done

            ! grep -al 'Kernel panic' "$work"/n?.log || fail "a kernel panicked"
            echo "vm.sh: ok: two nodes, and kubectl and helm as they are shipped asking the first: manifests written for Kubernetes applied (a Deployment of three told things by a ConfigMap and a Secret, its Service and Ingress, a StatefulSet whose claim got a volume made for it, and one of three with a claim and a volume for each replica across the two nodes, each back on its own volume's node after a restart), rolled out and running; a Job and a CronJob's Job, made by the clock, heard all of them through their Services (kubectl wait, kubectl logs); after kubectl rollout restart the StatefulSet's new pod had the file the old one wrote; a pod as a chart writes one had a ConfigMap's files (changed in it when the ConfigMap was, with no restart) and one of them alone (subPath), a Secret's file from memory with the mode it asked, two directories of its own (one in memory), what it was told by envFrom and by its own fields, no capability as a user who is not root, and found what its initContainer left; root without two capabilities had the others; told runAsNonRoot an image that names no user did not start and said why; a Deployment made, exposed, scaled and given another image by hand rolled out each time; port-forward was refused in words; helm install, upgrade and uninstall with --wait came back when the chart was ready ($n of helm); deleted, nothing was left; $stock" >&2
            exit 0

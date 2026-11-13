# Everything Samba writes is under /run: the image is read-only.
set -euf
d=/run/samba
mkdir -p "$d/private" "$d/state"
# The users, beside the image's own (nss_wrapper has Samba read these).
cp /etc/passwd "$d/passwd"
cp /etc/group "$d/group"
echo "kith-share:x:$KITH_SHARE_UID:$KITH_SHARE_GID::/:/sbin/nologin" >>"$d/passwd"
echo "kith-share:x:$KITH_SHARE_GID:" >>"$d/group"
n=0
for user in $KITH_SMB_USERS; do
  n=$((n + 1))
  echo "$user:x:$((60000 + n)):$KITH_SHARE_GID::/:/sbin/nologin" >>"$d/passwd"
done
export LD_PRELOAD=libnss_wrapper.so NSS_WRAPPER_PASSWD="$d/passwd" NSS_WRAPPER_GROUP="$d/group"
cat >"$d/smb.conf" <<CONF
[global]
server role = standalone server
smb ports = 445
disable netbios = yes
server min protocol = SMB3
smb encrypt = desired
map to guest = never
load printers = no
private dir = $d/private
state directory = $d/state
cache directory = $d/state
lock directory = $d/state
pid directory = $d
[$KITH_SHARE_NAME]
path = /share
read only = $KITH_SHARE_READ_ONLY
valid users = $KITH_SMB_USERS
force user = kith-share
force group = kith-share
CONF
n=0
for user in $KITH_SMB_USERS; do
  n=$((n + 1))
  password=
  eval "password=\$KITH_SMB_PASSWORD_$n"
  printf '%s\n%s\n' "$password" "$password" | smbpasswd -c "$d/smb.conf" -s -a "$user" >/dev/null
done
exec smbd -s "$d/smb.conf" --foreground --no-process-group --debug-stdout

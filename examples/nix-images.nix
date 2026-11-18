# Two images built with Nix, one layer for each store path in their closures (nixpkgs'
# dockerTools.buildLayeredImage): hello, and figlet beside it. Built off the node; the node
# has no Nix. See docs/guide/workloads.md, "An image from a Nix closure".
#
#   nix-build examples/nix-images.nix -A hello -o hello.tar
#   docker load -i hello.tar && docker tag hello:1 registry.example/hello:1
#   docker push registry.example/hello:1
{ pkgs ? import <nixpkgs> { } }:
{
  hello = pkgs.dockerTools.buildLayeredImage {
    name = "hello";
    tag = "1";
    contents = [ pkgs.hello ];
    config.Cmd = [ "/bin/hello" ];
  };
  figlet = pkgs.dockerTools.buildLayeredImage {
    name = "figlet";
    tag = "1";
    contents = [ pkgs.figlet ];
    config.Cmd = [ "/bin/figlet" "kith" ];
  };
}

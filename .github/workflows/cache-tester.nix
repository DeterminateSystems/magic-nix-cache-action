{ seed }:
derivation {
  name = "cache-test";
  system = builtins.currentSystem;

  builder = "/bin/sh";
  args = [ "-euxc" "echo \"$seed\" > $out" ];

  inherit seed;
}

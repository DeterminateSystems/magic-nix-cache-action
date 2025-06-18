{ seed }:
derivation {
  name = "cache-test";
  system = builtins.currentSystem;

  builder = "/bin/sh";
  args = [ "-euxc" "echo \"$seed\" > $out" ];

  inherit seed;

  deps = builtins.map
    (n: derivation {
      name = "cache-test-${toString n}";
      system = builtins.currentSystem;

      builder = "/bin/sh";
      args = [ "-euxc" "echo \"$seed\" > $out" ];

      inherit seed;
    })
    (builtins.genList (n: n) 500);
}

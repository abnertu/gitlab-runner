{
  lib,
}:
let
  rawInstances = import ./instances.nix;
  cases = builtins.fromJSON (builtins.readFile ./validation-cases.json);
  evaluate =
    instances:
    builtins.tryEval (
      builtins.deepSeq (import ../interface.nix {
        inherit lib;
        rawInstances = instances;
      }) true
    );
  canonical = import ../interface.nix { inherit lib rawInstances; };
  badAllowlist = rawInstances // {
    frontend = rawInstances.frontend // {
      runner = rawInstances.frontend.runner // {
        allowedImages = [ "docker.io/library/python:*" ];
      };
    };
  };
  unknownField = rawInstances // {
    frontend = rawInstances.frontend // {
      credential = "forbidden";
    };
  };
  overlappingRange = rawInstances // {
    dotnet = rawInstances.dotnet // {
      subordinateIdStart = rawInstances.frontend.subordinateIdStart;
    };
  };
in
assert (evaluate rawInstances).success;
assert builtins.all (
  case:
  let
    changed = lib.recursiveUpdate rawInstances.frontend (lib.setAttrByPath case.path case.value);
  in
  (evaluate { frontend = changed; }).success == case.valid
) cases;
assert
  !(evaluate (
    rawInstances
    // {
      dotnet = rawInstances.dotnet // {
        uid = rawInstances.frontend.uid;
      };
    }
  )).success;
assert
  !(evaluate (
    rawInstances
    // {
      dotnet = rawInstances.dotnet // {
        subordinateIdStart = rawInstances.frontend.subordinateIdStart + 65535;
      };
    }
  )).success;
assert
  (evaluate (
    rawInstances
    // {
      dotnet = rawInstances.dotnet // {
        subordinateIdStart = rawInstances.frontend.subordinateIdStart + 65536;
      };
    }
  )).success;
assert (evaluate { }).success;
assert (evaluate { inherit (rawInstances) frontend; }).success;
assert !(evaluate badAllowlist).success;
assert !(evaluate unknownField).success;
assert !(evaluate overlappingRange).success;
assert canonical.frontend.account.user == "gitlab-runner-frontend";
assert canonical.frontend.account.home == "/home/gitlab-runner-frontend";
assert canonical.frontend.account.subUid.count == 65536;
assert canonical.frontend.account.subUid == canonical.frontend.account.subGid;
assert canonical.frontend.runner.serviceName == "gitlab-runner-frontend";
assert canonical.frontend.runner.concurrent == 1;
true

{
  lib,
  stdenv,
  cmake,
  pkg-config,
  hyprutils,
  hyprland-qt-support,
  kdePackages,
  polkit,
  qt6,
  gcr_4,
  glib,
  json-glib,
  version ? "0",
}: let
  inherit (lib.sources) cleanSource cleanSourceWith;
  inherit (lib.strings) hasSuffix;
in
  stdenv.mkDerivation {
    pname = "noctalia-polkit";
    inherit version;

    src = cleanSourceWith {
      filter = name: _type: let
        baseName = baseNameOf (toString name);
      in
        ! (hasSuffix ".nix" baseName);
      src = cleanSource ../.;
    };

    nativeBuildInputs = [
      cmake
      pkg-config
      qt6.wrapQtAppsHook
    ];

    buildInputs = [
      hyprutils
      hyprland-qt-support
      polkit
      kdePackages.polkit-qt-1
      qt6.qtbase
      qt6.qtsvg
      qt6.qtwayland
      # For keyring-prompter
      gcr_4
      glib
      json-glib
    ];

    meta = {
      description = "A polkit authentication agent and keyring prompter";
      homepage = "https://github.com/anthonyhab/noctalia-polkit";
      license = lib.licenses.bsd3;
      maintainers = [lib.maintainers.fufexan];
      mainProgram = "noctalia-polkit";
      platforms = lib.platforms.linux;
    };
  }

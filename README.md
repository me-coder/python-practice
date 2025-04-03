# Usage
This project is to study the use of _Dev Containers_ in [Visual Studio Code](https://code.visualstudio.com/)/[Codium](https://vscodium.com/).

## Steps to get started
1. Install [Docker](https://docs.docker.com/get-started/get-docker/) or [Podman](https://podman.io/docs/installation)
1. In extensions search _ms-vscode-remote.remote-containers_ and install the extension
1. Search for `Dev › Containers: Docker Path` in settings
1. Modify the value with `docker` or `podman` depending upon the local installation
1. If interested, open file `.devcontainer/devcontainer.json` and study the contents
    **Suggestion**: DO NOT uncomment the **_mounts_** section
1. Open this workspace in a **_python:slim_** container
    1. Open **Command Palette** ress _Ctrl+Shift+P_ (Windows) or _Command+Shift+P_ (MacOS)
    1. Type: _"Dev Containers: Rebuild and Reopen in Container"_ (_Ensure docker/podman is already running in background_)

You are ready to setup your environment in the launched _python:slim_ container.

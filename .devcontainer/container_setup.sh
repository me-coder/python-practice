#!/usr/bin/env bash

apt-get update
apt-get install -y git
# apt-get install -y direnv
# mkdir -p ~/.config/direnv
# cat >~/.config/direnv/direnv.toml<<EOT
# [whitelist]
# prefix = [ "/python" ]
# EOT
# echo eval '"$(direnv hook bash)"' >> ~/.bashrc

python -m venv ${containerWorkspaceFolder}/.venv
python -m pip install --upgrade pip

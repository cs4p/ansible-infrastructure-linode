#!/usr/bin/env bash
echo "Updating Inventory"
python -c "import scripts.combinedScripts as s;s.deploy()"
cp ./output/ssh_keys/* /Users/dan/.ssh/
cp ./output/ssh_linodes_config /Users/dan/.ssh/config
chmod 600 /Users/dan/.ssh/*_private.key
# echo "Setting up any new hosts..."
# ansible-playbook --ask-vault-pass -i ./hosts ./play_newHost.yml
echo "Starting Configuration..."
#ansible-playbook -i ./hosts ./play.yml -b --ask-become-pass --ask-vault-pass
ansible-playbook -i ./hosts ./play.yml -b --ask-become-pass -vv
echo "Done"

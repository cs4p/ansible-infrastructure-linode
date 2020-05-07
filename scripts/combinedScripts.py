import linode_api4 as linode_api
import crypt
import random
import string

from Crypto.PublicKey import RSA

pathToProject = '/Users/dan/PycharmProjects/ansible-infrastructure'

def createClient():
    # TODO: Store linode API Key safely
    linodeAPIclient = linode_api.LinodeClient("832b1274d8d3d6c502885706005f9c9a8cc90059aa606a1f856e849e9809975a")
    return linodeAPIclient


def updateInventory(linodeAPIclient):
    my_linodes = linodeAPIclient.linode.instances()

    linode_dct = {}
    nessus_list = []
    # erase all output files
    filesList = ['/output/ssh_linodes_config', '/output/hosts_file', '/output/nessus.txt', '/group_vars/all.yml']
    for file in filesList:
        open(pathToProject+file, 'w').close()

    for current_linode in my_linodes:
        print("creating "+current_linode.label)
        linode_dct["linode_id"] = str(current_linode.id)
        linode_dct["domain_name"] = current_linode.label
        linode_dct["ansible_host"] = current_linode.ips.ipv4.public[0].address
        linode_dct["private_ip"] = current_linode.ips.ipv4.private[0].address
        # this assumes you have no linodes with labels that differ only after the last "."
        userName = current_linode.label[:current_linode.label.rfind('.')]
        user_info = createAccount(userName, pathToProject+'/output/ssh_keys/' + userName)
        linode_dct["user"] = user_info["user"]
        linode_dct["password"] = user_info["password"]
        linode_dct["hashed_password"] = user_info["hashed_password"]
        linode_dct["ssh_public_key"] = user_info["ssh_public_key"]
        # create credentials for root account
        user_info = createAccount('root', pathToProject+'/output/ssh_keys/' + userName + '_root')
        linode_dct["root_user"] = user_info["user"]
        linode_dct["root_password"] = user_info["password"]
        linode_dct["root_hashed_password"] = user_info["hashed_password"]
        linode_dct["root_ssh_public_key"] = user_info["ssh_public_key"]
        linode_dct["rebuild_linode_cmd"] = "import scripts.combinedScripts as s;s.rebuildLinode('"+linode_dct["linode_id"]+"','"+linode_dct["root_hashed_password"]+"')"
        if 'wordpress' in current_linode.tags:
            linode_dct["mysql_db"] = linode_dct["user"]
            linode_dct["mysql_user"] = "wp_" + linode_dct["user"] + "_db_user"
            linode_dct["mysql_user_password"] = createPassword()

        fd_ansible = open(pathToProject+"/host_vars/" + userName + '.yml', 'w')
        fd_ssh = open(pathToProject+"/output/ssh_linodes_config", 'a')
        fd_hosts = open(pathToProject+"/output/hosts_file", 'a')

        # create host_var file
        for key, value in linode_dct.items():
#            fd_ansible.write(str(key + ": '" + value + "'\n"))
            fd_ansible.write(str(key + ': "' + value + '"\n'))

        # Create entries suitable for an ssh config file
        fd_ssh.write(str("Host " + linode_dct["domain_name"] + '\n'))
        fd_ssh.write(str("\tHostName " + linode_dct["ansible_host"] + '\n'))
        fd_ssh.write(str('\tUser ' + linode_dct['user'] + '\n'))
        fd_ssh.write(str("\tPort 22" + '\n'))
        fd_ssh.write(str("\tIdentityFile ~/.ssh/" + linode_dct['user'] + '_private.key\n'))
        fd_ssh.write('\n')

        # Create entries suitable for a host file
        fd_hosts.write(str(linode_dct["ansible_host"] + '\t' + linode_dct["domain_name"] + '\n'))

        # csv IP List (for nessus)
        nessus_list.append(str(linode_dct["ansible_host"]))

        # close all the files
        fd_ansible.close()
        fd_ssh.close()
        fd_hosts.close()

        # reset the dictionary
        linode_dct = {}

    # Write csv string to a file and close
    fd_nessus = open(pathToProject+"/output/nessus.txt", 'a')
    fd_nessus.write(",".join(nessus_list))
    fd_nessus.close()


def createLinode(label, linodeAPIclient):
    region = 'ca-central'
    ltype = 'g6-nanode-1'
    authorized_keys = linodeAPIclient.profile.ssh_keys().first().ssh_key
    image = 'linode/ubuntu18.04'
    root_pass = createPassword()

    new_linode = linodeAPIclient.linode.instance_create(
        ltype,
        region,
        image=image,
        authorized_keys=authorized_keys,
        root_pass=root_pass,
        label=label)
    new_linode.ip_allocate()
    results = {'linode_id': new_linode, 'root_pass': root_pass}
    return results


# TODO add function to backup linode
def backupLinode(linode_id, linodeAPIclient):
    my_linodes = linodeAPIclient.linode.instances()
    loaded_linode = linodeAPIclient.load(my_linodes.lists[0][0], linode_id)


def rebuildLinode(linode_id, root_pass):
    linodeAPIclient = createClient()
    my_linodes = linodeAPIclient.linode.instances()
    loaded_linode = linodeAPIclient.load(my_linodes.lists[0][0], linode_id)
    image = 'linode/ubuntu18.04'
    loaded_linode.rebuild(image, root_pass)
    # return root_pass


def testMethod(linode_id, root_pass):
    print(linode_id, root_pass)


def createPassword():
    specialCharacters = "!$%()-/:=?@_{|}"
    password_characters = string.ascii_letters + string.digits + specialCharacters
    password = ''.join(random.choice(password_characters) for i in range(40))
    return password


def hashPassword(password):
    randomsalt = ''.join(random.sample(string.ascii_letters, 8))
    hashedPassword = crypt.crypt(password, '$5$' + randomsalt + '$')
    return hashedPassword


def createSSH_Key(user, ssh_key_file):
    key = RSA.generate(2048)
    pubkey = key.publickey()
    pubkeyStr = str(pubkey.exportKey('PEM').decode('UTF-8'))

    content_file = open(ssh_key_file + "_private.key", 'wb')
    content_file.write(key.exportKey('PEM'))
    content_file.close()
    content_file = open(ssh_key_file + "_public.key", 'wb')
    content_file.write(pubkey.exportKey('PEM'))
    content_file.close()
    return pubkeyStr


def createAccount(user, output_file):
    results = {"user": user, "password": createPassword()}
    results["hashed_password"] = hashPassword(results["password"])
    results["ssh_public_key"] = createSSH_Key(results["user"], output_file)
    return results


def deploy():
    print("opening linode API connection")
    client = createClient()
    # updateInventory looks up all current linodes and creates a host_vars file for each which includes new passwords and public keys
    print('updating inventory')
    updateInventory(client)
    print('done')

    # generate some common passwords used on all servers and store them in a global variables file
    print('update secrets')
    secretsFile = pathToProject+'/group_vars/all.yml'
    # all hosts need the mysql root password so they can create accounts and databases on shared sql server
    mysql_root_password = createPassword()
    # create an account on all servers for the vulnerability scanner
    nessus_dict = createAccount('nessus', pathToProject+'/output/ssh_keys/nessus')
    # write everythign to secrets file
    sf = open(secretsFile, 'w')
    sf.write("mysql_root_password: '" + mysql_root_password + "'\n")
    for k, v in nessus_dict.items():
        sf.write(str(k + ": '" + v + "'\n"))
    print('done')

# deploy()

# python3 -c "import scripts.linodeInventory as l;import scripts.generateSecrets as s;l.testMethod('linode_id','root_pass','authorized_keys')"

# python3 -c "import scripts.linodeInventory as l;import scripts.generateSecrets as s;l.rebuildLinode('linode_id','root_pass','authorized_keys')"

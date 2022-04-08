#! /bin/bash

sudo apt-get remove docker docker-engine docker.io containerd runc
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg lsb-release
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io
sudo docker run hello-world

echo "Printing the current module"
echo $module

# To cleanup the user details
cp BaseVmImageInit /opt/
cp Run.sh /opt/
cp StartVirtualMachine.sh /opt/
chmod +x /opt/Run.sh
chmod +x /opt/StartVirtualMachine.sh
chmod +x /opt/BaseVmImageInit

docker build . -t $module

(crontab -l; echo "@reboot cd /opt; sudo ./StartVirtualMachine.sh > VmImageInit.log") | crontab -

/usr/sbin/waagent -force -deprovision+user && export HISTSIZE=0 && sync

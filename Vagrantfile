# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|

  config.vm.box = "ubuntu/trusty64"

  config.vm.hostname = "initscript-vm"

  config.vm.synced_folder ".", "/home/vagrant/src"
  config.vm.synced_folder "../../python-neutrinoclient", "/home/vagrant/python-neutrinoclient"

  config.vm.provider "virtualbox" do |vb|
    vb.memory = "512"
    vb.cpus = 1
  end

  config.vm.provision "shell", inline: <<-SHELL
    sudo apt-get update
    sudo apt-get install -y git curl python3 python3-pip
    sudo pip3 install virtualenv
    cd /home/vagrant/src/ && virtualenv venv && source venv/bin/activate
    pip3 install -r /home/vagrant/src/requirements.txt
  SHELL
end

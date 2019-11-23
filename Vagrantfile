# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.provider "virtualbox" do |vb, override|
    vb.gui = false
    vb.memory = 512
  end
  config.vm.box = "archlinux/archlinux"
  config.vm.synced_folder ".", "/home/vagrant/grewrite"
  config.vm.provision :shell, path: "config/vagrant/provision.sh"
end

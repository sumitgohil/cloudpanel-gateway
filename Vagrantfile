# frozen_string_literal: true

require "rbconfig"

versions = File.readlines(File.join(__dir__, "lab", "versions.env"), chomp: true).each_with_object({}) do |line, values|
  next if line.empty? || line.start_with?("#")

  key, value = line.split("=", 2)
  values[key] = value if key && value
end

host_cpu = RbConfig::CONFIG["host_cpu"]
architecture = host_cpu.match?(/arm|aarch64/i) ? "arm64" : "amd64"
lab_ip = ENV.fetch("CPGW_LAB_IP", versions.fetch("LAB_IP"))
source_archive = ENV.fetch("CPGW_LAB_SOURCE_ARCHIVE", File.join(__dir__, "lab", ".build", "source.tar"))

Vagrant.configure("2") do |config|
  config.vm.box = versions.fetch("VAGRANT_BOX")
  config.vm.box_version = versions.fetch("VAGRANT_BOX_VERSION")
  config.vm.box_architecture = architecture
  config.vm.box_check_update = false
  config.vm.hostname = "cloudpanel-gateway-test-lab"
  config.vm.boot_timeout = 900
  config.vm.network "private_network", ip: lab_ip

  # The source is delivered as an explicit Git archive by scripts/test-lab.
  # Do not mount the repository: that could expose untracked credentials.
  config.vm.synced_folder ".", "/vagrant", disabled: true

  config.vm.provider "virtualbox" do |provider|
    provider.name = "cloudpanel-gateway-test-lab"
    provider.cpus = 2
    provider.memory = 4096
  end

  config.vm.provision "file", source: source_archive, destination: "/tmp/cloudpanel-gateway-source.tar"
  config.vm.provision "file", source: "lab/versions.env", destination: "/tmp/cloudpanel-gateway-lab-versions.env"
  config.vm.provision "file", source: "lab/verify.sh", destination: "/tmp/cloudpanel-gateway-lab-verify.sh"
  config.vm.provision "shell", path: "lab/provision.sh", privileged: true
end

VMS = [
    {
        name: "net_ops",
        box: "ubuntu/jammy64",
        private_ip: "192.168.56.10",
        ssh_port: 2201,
        memory: 6144,
        cpus: 4,
        forwarded_ports: [
            {guest: 8055, host: 8055},
            {guest: 22, host: 2201},
            {guest: 5636, host: 5636},  # EveBox
            # --- Lab 3 ---
            {guest: 8161, host: 8161},  # ActiveMQ Web Console
            {guest: 8080, host: 8080},  # Jenkins
            {guest: 9001, host: 9001},  # MinIO Console
            # --- Lab 4 ---
            {guest: 3000, host: 3000}   # OWASP Juice Shop
        ]
    },
]

Vagrant.configure("2") do |config|
    VMS.each do |vm|
        config.vm.define vm[:name] do |v|
            v.vm.box = vm[:box]

            # Сетевые настройки
            v.vm.network "private_network", ip: vm[:private_ip]
            #v.vm.network "public_network", bridge: "enp0s31f6", ip: vm[:public_ip]

            # Проброс портов
            vm[:forwarded_ports].each do |fp|
                v.vm.network "forwarded_port",
                    guest: fp[:guest],
                    host: fp[:host],
                    auto_correct: false
            end

            # Настройки VirtualBox
            v.vm.provider "virtualbox" do |vb|
                vb.name = vm[:name]
                vb.memory = vm[:memory]
                vb.cpus = vm[:cpus]
                vb.customize ["modifyvm", :id, "--ioapic", "on"]
                vb.customize ["modifyvm", :id, "--natdnsproxy1", "on"]
                vb.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
            end

            # Provisioning: создание пользователя devopsuser и настройка SSH
            v.vm.provision "shell", inline: <<-SHELL
                # Создаем нового пользователя devopsuser
                useradd -m -s /bin/bash devopsuser

                # Добавляем пользователя в группу sudo
                usermod -aG sudo devopsuser

                # Настроим sudo без пароля
                echo 'devopsuser ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/99_devopsuser

                # Создаем .ssh директорию для devopsuser
                mkdir -p /home/devopsuser/.ssh

                # Добавляем публичный ключ в authorized_keys для devopsuser
                echo "#{File.read('devopsuser_rsa.pub')}" >> /home/devopsuser/.ssh/authorized_keys

                # Устанавливаем правильные права доступа
                chown -R devopsuser:devopsuser /home/devopsuser/.ssh
                chmod 700 /home/devopsuser/.ssh
                chmod 600 /home/devopsuser/.ssh/authorized_keys
            SHELL
        end
    end
end

require 'yaml'

inventory = {
  "all" => {
    "hosts" => {}
  }
}

VMS.each do |vm|
  inventory["all"]["hosts"][vm[:name]] = {
    "ansible_host" => "127.0.0.1",
    "ansible_port" => vm[:ssh_port],
    "ansible_user" => "devopsuser",
    "ansible_ssh_private_key_file" => "devopsuser_rsa",
    "internal_host" => vm[:private_ip],
    "ansible_ssh_extra_args" => "-o StrictHostKeyChecking=no"
  }
end

File.write("./ansible/inventory/inventory.yml", inventory.to_yaml)
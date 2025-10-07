#!/usr/bin/env python3
import base64
import os
import yaml
import libvirt
import jinja2
import subprocess
import grp
import pwd
import time
import json
import threading
import shutil
from typing import Dict, List, Union, Optional
from datetime import datetime

# Chemins et constants
ISO_DIR = "/var/lib/libvirt/isos"
VM_IMAGES_DIR = "/var/lib/libvirt/images"
CLOUD_INIT_ISO_DIR = "/var/lib/libvirt/cloud_init_isos"
TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")
SCRIPTS_DIR = os.path.join(os.path.dirname(__file__), "scripts")
FILES_DIR = os.path.join(os.path.dirname(__file__), "files")
OVMF_NVRAM_DIR = "/var/lib/libvirt/qemu/nvram"

# Codes de couleur pour les logs
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def log_message(message: str, level: str = "INFO") -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if level == "INFO":
        print(f"{Colors.OKBLUE}[{timestamp}] [INFO]{Colors.ENDC} {message}")
    elif level == "SUCCESS":
        print(f"{Colors.OKGREEN}[{timestamp}] [SUCCESS]{Colors.ENDC} {message}")
    elif level == "WARNING":
        print(f"{Colors.WARNING}[{timestamp}] [WARNING]{Colors.ENDC} {message}")
    elif level == "ERROR":
        print(f"{Colors.FAIL}[{timestamp}] [ERROR]{Colors.ENDC} {message}")
    else:
        print(f"[{timestamp}] [{level}] {message}")

def run_command(
    command: Union[str, List[str]],
    show_output: bool = False,
    check: bool = True,
    cwd: Optional[str] = None
) -> subprocess.CompletedProcess:
    log_message(f"Exécution de la commande: {' '.join(command) if isinstance(command, list) else command}")
    if show_output:
        result = subprocess.run(
            command,
            shell=isinstance(command, str),
            check=check,
            cwd=cwd
        )
    else:
        with open(os.devnull, 'w') as devnull:
            result = subprocess.run(
                command,
                shell=isinstance(command, str),
                stdout=devnull,
                stderr=devnull,
                check=check,
                cwd=cwd
            )
    return result

# Initialiser Jinja2 pour les templates
env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(TEMPLATES_DIR),
    trim_blocks=True,
    lstrip_blocks=True
)

def decode_base64_fields(data):
    if isinstance(data, dict):
        decoded_dict = {}
        for key, value in data.items():
            if key in ['out-data', 'err-data'] and isinstance(value, str):
                try:
                    decoded_value = base64.b64decode(value).decode('utf-8')
                    decoded_dict[key] = decoded_value
                except (base64.binascii.Error, UnicodeDecodeError):
                    decoded_dict[key] = value
            else:
                decoded_dict[key] = decode_base64_fields(value)
        return decoded_dict
    elif isinstance(data, list):
        return [decode_base64_fields(item) for item in data]
    else:
        return data

def _detect_ovmf_paths() -> Dict[str, str]:
    candidates = [
        ("/usr/share/OVMF/OVMF_CODE.fd", "/usr/share/OVMF/OVMF_VARS.fd"),
        ("/usr/share/OVMF/OVMF_CODE_4M.fd", "/usr/share/OVMF/OVMF_VARS_4M.fd"),
    ]
    for code, vars_ in candidates:
        if os.path.exists(code) and os.path.exists(vars_):
            return {"code": code, "vars": vars_}
    return {"code": None, "vars": None}

class InfraDeployer:
    def __init__(self, yaml_file: str):
        self.yaml_file = yaml_file
        self.conn = None
        self._infra = None

    @property
    def infra(self):
        if self._infra is None:
            raise RuntimeError("L'infrastructure n'a pas été chargée. Appelez load_infra() d'abord.")
        return self._infra

    @infra.setter
    def infra(self, value):
        self._infra = value

    def check_prerequisites(self):
        errors = []
        # Groupes
        user = pwd.getpwuid(os.getuid()).pw_name
        user_groups = [g.gr_name for g in grp.getgrall() if user in g.gr_mem] + [grp.getgrgid(pwd.getpwuid(os.getuid()).pw_gid).gr_name]
        for group in ['kvm', 'libvirt']:
            if group not in set(user_groups):
                errors.append(f"L'utilisateur doit être dans le groupe '{group}' (sudo usermod -aG {group} $USER)")

        # libvirtd actif
        try:
            run_command(['systemctl', 'is-active', 'libvirtd'], check=True)
        except subprocess.CalledProcessError:
            errors.append("Le service libvirtd n'est pas actif (sudo systemctl start libvirtd)")

        # Répertoires & droits
        for dir_path in [ISO_DIR, VM_IMAGES_DIR, CLOUD_INIT_ISO_DIR, SCRIPTS_DIR, FILES_DIR, OVMF_NVRAM_DIR]:
            if not os.path.exists(dir_path):
                errors.append(f"Répertoire introuvable: {dir_path} (sudo mkdir -p {dir_path})")
            else:
                if not os.access(dir_path, os.W_OK):
                    errors.append(f"Permissions insuffisantes sur {dir_path} (sudo chown -R $USER:$USER {dir_path})")

        # Connexion libvirt
        try:
            self.conn = libvirt.open("qemu:///system")
            if self.conn is None:
                errors.append("Impossible de se connecter à libvirt (vérifiez les permissions)")
        except Exception as e:
            errors.append(f"Erreur de connexion à libvirt: {e}")
        if errors:
            for error in errors:
                log_message(error, "ERROR")
            raise RuntimeError("Prérequis non satisfaits")

    def load_infra(self):
        with open(self.yaml_file, 'r') as f:
            self.infra = yaml.safe_load(f)
        self.validate()

    def validate(self):
        errors = []
        # ISO
        for vm in self.infra['vms']:
            if 'cloud_init' in vm and 'iso' in vm['cloud_init']:
                iso_path = os.path.join(ISO_DIR, vm['cloud_init']['iso'])
                if not os.path.exists(iso_path):
                    errors.append(f"ISO introuvable: {iso_path}")
        # VM sources
        vm_names = {vm['name'] for vm in self.infra.get('vms', [])}
        existing_vms = {dom.name() for dom in self.conn.listAllDomains()}
        for vm in self.infra.get('vms', []):
            if 'clone_init' in vm:
                source_vm_name = vm['clone_init']['source_vm']
                if source_vm_name not in existing_vms and source_vm_name not in vm_names:
                    errors.append(f"VM source {source_vm_name} non définie ni trouvée (utilisée par {vm['name']})")
                elif source_vm_name in vm_names:
                    source_vm_index = next((i for i, v in enumerate(self.infra.get('vms', [])) if v['name'] == source_vm_name), None)
                    clone_vm_index = next((i for i, v in enumerate(self.infra.get('vms', [])) if v['name'] == vm['name']), None)
                    if source_vm_index is not None and clone_vm_index is not None and source_vm_index > clone_vm_index:
                        errors.append(f"VM source {source_vm_name} doit être définie avant la VM clonée {vm['name']}")
        # Réseaux
        defined_networks = {net['name'] for net in self.infra.get('networks', [])}
        existing_networks = {net.name() for net in self.conn.listAllNetworks()}
        for vm in self.infra.get('vms', []):
            for net_config in vm.get('networks', []):
                network_name = net_config['name']
                if network_name not in defined_networks and network_name not in existing_networks:
                    errors.append(f"Réseau {network_name} non défini/absent (utilisé par {vm['name']})")
        # Scripts
        for vm in self.infra.get('vms', []):
            for script in vm.get('post_install_scripts', []):
                script_path = os.path.join(SCRIPTS_DIR, script)
                if not os.path.exists(script_path):
                    errors.append(f"Script introuvable: {script_path} (utilisé par {vm['name']})")
        if errors:
            raise ValueError("Erreurs de validation:\n" + "\n".join(f"  - {e}" for e in errors))

    def network_exists(self, name: str) -> bool:
        return any(net.name() == name for net in self.conn.listAllNetworks(0))

    def network_is_active(self, name: str) -> bool:
        for net in self.conn.listAllNetworks():
            if net.name() == name:
                return net.isActive()
        return False

    def vm_exists(self, name: str) -> bool:
        return any(domain.name() == name for domain in self.conn.listAllDomains(0))

    def create_network(self, network: Dict):
        if self.network_exists(network['name']):
            log_message(f"Réseau {network['name']} existe déjà, ignoré", "WARNING")
            return
        template = env.get_template('network.xml.j2')
        network_xml = template.render(network=network, netmask=netmask)
        try:
            self.conn.networkDefineXML(network_xml)
            log_message(f"Réseau {network['name']} créé", "SUCCESS")
        except libvirt.libvirtError as e:
            log_message(f"Erreur lors de la création du réseau {network['name']}: {e}", "ERROR")
            raise

    def start_network(self, name: str):
        try:
            log_message(f"Tentative d'activation du réseau {name}...", "INFO")
            net = self.conn.networkLookupByName(name)
            if net.isActive():
                log_message(f"Réseau {name} est déjà actif", "WARNING")
                return
            log_message(f"Démarrage du réseau {name}...", "INFO")
            net.create()
            log_message(f"Réseau {name} activé", "SUCCESS")
        except libvirt.libvirtError as e:
            log_message(f"Erreur lors de l'activation du réseau {name}: {e}", "ERROR")
            raise

    def deploy_networks(self):
        for network in self.infra.get('networks', []):
            log_message(f"Déploiement du réseau {network['name']}...", "INFO")
            self.create_network(network)
            self.start_network(network['name'])

    def wait_for_cdrom(self, vm_name: str, timeout: int = 30, interval: int = 1) -> bool:
        start_time = time.time()
        while time.time() - start_time < timeout:
            result = self.execute_via_qemu_agent(vm_name, "lsblk /dev/sr0")
            result_decoded = decode_base64_fields(result)
            if result_decoded.get('success', False) and \
               'exitcode' in result_decoded.get('output', {}).get('return', {}) and \
               result_decoded['output']['return']['exitcode'] == 0:
                log_message("Périphérique CD-ROM prêt", "SUCCESS")
                return True
            time.sleep(interval)
        log_message("Timeout atteint en attendant le périphérique CD-ROM", "ERROR")
        return False

    def apply_init_via_agent(self, vm: Dict):
        if 'cloud_init' in vm:
            log_message(f"Configuration cloud_init trouvée pour {vm['name']}", "INFO")
            self.apply_cloud_init_via_agent(vm)
        elif 'clone_init' in vm:
            log_message(f"Configuration clone_init trouvée pour {vm['name']}", "INFO")
            self.apply_clone_init_via_agent(vm)
        else:
            log_message(f"Aucune configuration d'initialisation trouvée pour {vm['name']}", "ERROR")

    def apply_cloud_init_via_agent(self, vm: Dict):
        if 'cloud_init' not in vm:
            log_message(f"Aucune configuration cloud_init trouvée pour {vm['name']}", "ERROR")
            return False
        try:
            log_message(f"Application de la configuration cloud_init pour {vm['name']}", "INFO")
            return True
        except Exception as e:
            log_message(f"Erreur lors de l'application de cloud_init pour {vm['name']}: {e}", "ERROR")
            return False

    def apply_clone_init_via_agent(self, vm: Dict):
        if 'clone_init' not in vm:
            log_message(f"Aucune configuration clone_init trouvée pour {vm['name']}", "ERROR")
            return False
        try:
            config = vm['clone_init']['user_data']['autoinstall']
            identity = config.get('identity', {})
            hostname = identity.get('hostname')
            if hostname:
                if not self.execute_via_qemu_agent(vm['name'], f"hostnamectl set-hostname {hostname}")['success']:
                    log_message(f"Erreur hostname pour {vm['name']}", "ERROR"); return False
            username = identity.get('username'); password = identity.get('password')
            if username and password:
                if not self.execute_via_qemu_agent(vm['name'], f"bash -lc \"echo '{username}:{password}' | chpasswd\"")['success']:
                    log_message(f"Erreur user/pass pour {vm['name']}", "ERROR"); return False
            network = config.get('network', {})
            if network:
                netplan_config = yaml.dump({'network': network}, default_flow_style=False)
                self._write_file_via_agent(vm['name'], "/etc/netplan/50-cloud-init.yaml",
                                           base64.b64encode(netplan_config.encode()).decode())
                if not self.execute_via_qemu_agent(vm['name'], "netplan apply")['success']:
                    log_message(f"Erreur netplan pour {vm['name']}", "ERROR"); return False
            packages = config.get('packages', [])
            for pkg in packages:
                if not self.execute_via_qemu_agent(vm['name'], f"apt-get update && apt-get install -y {pkg}")['success']:
                    log_message(f"Erreur installation paquet {pkg} pour {vm['name']}", "ERROR"); return False
            late_commands = config.get('late_commands', [])
            for cmd in late_commands:
                if isinstance(cmd, dict): continue
                if not self.execute_via_qemu_agent(vm['name'], cmd)['success']:
                    log_message(f"Erreur late_command: {cmd}", "ERROR"); return False
            log_message(f"Configuration clone_init appliquée pour {vm['name']}", "SUCCESS")
            return True
        except Exception as e:
            log_message(f"Erreur clone_init pour {vm['name']}: {e}", "ERROR")
            return False

    def _eject_all_cdroms(self, name: str):
        """Éjecte tous les lecteurs CD-ROM présents, sans supposer d'alias/target."""
        try:
            xml = self.conn.lookupByName(name).XMLDesc(0)
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml)
            for cd in root.findall("./devices/disk[@device='cdrom']"):
                tgt = cd.find('target')
                if tgt is not None and tgt.get('dev'):
                    targetdev = tgt.get('dev')
                    run_command(['virsh', 'change-media', name, targetdev, '--eject', '--config'], check=False)
        except Exception:
            pass

    def _safe_define_domain_xml(self, name: str, new_xml: str):
        """Redéfinit proprement (gère ‘existe déjà’, NVRAM, snapshots…)."""
        try:
            dom = self.conn.lookupByName(name)
            if dom.isActive():
                dom.destroy()
                log_message(f"VM {name} arrêtée pour redéfinition", "SUCCESS")
        except libvirt.libvirtError:
            dom = None

        try:
            self.conn.defineXML(new_xml)
            log_message(f"Définition {name} mise à jour (defineXML)", "SUCCESS")
            return
        except libvirt.libvirtError as e:
            msg = str(e)
            if "existe déjà" not in msg and "already exists" not in msg:
                raise

        if dom is None:
            dom = self.conn.lookupByName(name)

        flags = 0
        for attr in (
            'VIR_DOMAIN_UNDEFINE_KEEP_NVRAM',
            'VIR_DOMAIN_UNDEFINE_MANAGED_SAVE',
            'VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA',
            'VIR_DOMAIN_UNDEFINE_CHECKPOINTS_METADATA',
        ):
            flags |= getattr(libvirt, attr, 0)

        try:
            if flags:
                dom.undefineFlags(flags)
            else:
                dom.undefine()
            log_message(f"Ancienne définition {name} supprimée (undefine)", "SUCCESS")
        except libvirt.libvirtError as e:
            log_message(f"undefineFlags a échoué pour {name}: {e}", "WARNING")
            run_command(['virsh', 'undefine', name, '--nvram', '--managed-save',
                         '--snapshots-metadata', '--checkpoints-metadata'], check=False)

        self.conn.defineXML(new_xml)
        log_message(f"Définition {name} recréée", "SUCCESS")

    def _sanitize_xml_for_clone(self, xml: str, target_name: str, vm_cfg: Dict) -> str:
        """Nettoie un XML de domaine pour le clonage (UUID, NVRAM, serials NVMe, MACs)."""
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml)

        # name
        name_el = root.find('name')
        if name_el is not None:
            name_el.text = target_name

        # UUID : supprimer
        uuid_el = root.find('uuid')
        if uuid_el is not None:
            root.remove(uuid_el)

        # OVMF NVRAM
        os.makedirs(OVMF_NVRAM_DIR, exist_ok=True)
        nvram_el = root.find('./os/nvram')
        if nvram_el is not None:
            new_vars = os.path.join(OVMF_NVRAM_DIR, f"{target_name}_VARS.fd")
            src_vars = vm_cfg.get('ovmf_vars_template') or "/usr/share/OVMF/OVMF_VARS.fd"
            if not os.path.exists(new_vars) and os.path.exists(src_vars):
                shutil.copyfile(src_vars, new_vars)
            nvram_el.text = new_vars

        # Contrôleur NVMe : impose un serial
        devices = root.find('devices')
        ctrl = root.find("./devices/controller[@type='nvme']")
        if ctrl is None:
            ctrl = ET.SubElement(devices, 'controller', {'type': 'nvme', 'index': '0'})
        serial_el = ctrl.find('serial')
        if serial_el is None:
            serial_el = ET.SubElement(ctrl, 'serial')
        ctrl_serial = vm_cfg.get('nvme_controller_serial', f"{target_name}-nvme0")
        serial_el.text = ctrl_serial

        # Disques NVMe : serials + cibles cohérentes, boot order sur le 1er
        i = 0
        for d in root.findall("./devices/disk[@device='disk']"):
            tgt = d.find('target')
            if tgt is None:
                tgt = ET.SubElement(d, 'target', {'bus': 'nvme', 'dev': 'nvme0n1'})
            i += 1
            tgt.set('bus', 'nvme')
            tgt.set('dev', f'nvme0n{i}')
            dser = d.find('serial')
            if dser is None:
                dser = ET.SubElement(d, 'serial')
            dser.text = f"{target_name}-nvme0n{i}"
            # boot order sur le 1er disque
            for b in d.findall('boot'):
                d.remove(b)
            if i == 1:
                ET.SubElement(d, 'boot', {'order': '1'})

        # Interfaces réseau : si MAC non imposée → on supprime pour auto-gen
        nets_cfg = {n['name']: n for n in vm_cfg.get('networks', [])}
        for iface in root.findall("./devices/interface"):
            mac = iface.find('mac')
            src = iface.find('source')
            keep_mac = False
            if src is not None and 'network' in src.attrib:
                netname = src.attrib['network']
                if netname in nets_cfg and nets_cfg[netname].get('mac'):
                    keep_mac = True
                    if mac is None:
                        mac = ET.SubElement(iface, 'mac')
                    mac.set('address', nets_cfg[netname]['mac'])
            if not keep_mac and mac is not None:
                iface.remove(mac)

        return ET.tostring(root, encoding='unicode')

    # def finalize_vm_post_install(self, vm: Dict):
    #     """
    #     Post-install: attendre l’extinction, éjecter les CD-ROM,
    #     redéfinir via le template final UEFI+NVMe (avec NVRAM dédiée), puis démarrer.
    #     """
    #     name = vm['name']

    #     # A) Attendre la fin d'install
    #     self.wait_for_vm_shutdown(name)

    #     # B) Éjecter cdroms (sans supposer sata0-0-x)
    #     # self._eject_all_cdroms(name)

    #     # C) OVMF
    #     ovmf = _detect_ovmf_paths()
    #     vm = dict(vm)
    #     os.makedirs(OVMF_NVRAM_DIR, exist_ok=True)
    #     vm["ovmf_code"] = ovmf["code"] or "/usr/share/OVMF/OVMF_CODE.fd"
    #     vm["ovmf_vars_path"] = os.path.join(OVMF_NVRAM_DIR, f"{name}_VARS.fd")
    #     if ovmf["vars"] and not os.path.exists(vm["ovmf_vars_path"]):
    #         shutil.copyfile(ovmf["vars"], vm["ovmf_vars_path"])

    #     # D) Redéfinir via template final
    #     template = env.get_template('vm.xml.j2')
    #     vm_xml = template.render(vm=vm)
    #     self._safe_define_domain_xml(name, vm_xml)

    #     # E) Démarrer
    #     self.start_vm(name)

    def finalize_vm_post_install(self, vm: Dict):
        """
        Finalise proprement la VM après installation sans perdre les disques :
        - attend l'arrêt,
        - enlève les CD-ROM (install/cloud-init),
        - passe en UEFI/OVMF (pflash) et prépare le VARS,
        - ajoute un contrôleur NVMe s'il manque,
        - met l'ordre de boot sur le premier disque NVMe,
        - supprime d'éventuels <kernel>/<initrd>/<cmdline> laissés par l'install,
        - redéfinit le domaine avec l'XML modifié.
        """
        import xml.etree.ElementTree as ET
        name = vm['name']

        # 1) Attendre que la VM s'éteigne (fin d’install)
        self.wait_for_vm_shutdown(name)

        # 2) Récupérer l'XML courant
        dom = self.conn.lookupByName(name)
        xml = dom.XMLDesc(0)
        root = ET.fromstring(xml)

        # 3) Nettoyage des CD-ROM + préparation devices
        devices = root.find('devices')
        if devices is None:
            raise RuntimeError("XML invalide: section <devices> manquante")

        # Retirer tous les CD-ROM (device='cdrom')
        for d in list(devices.findall("disk")):
            if d.get('device') == 'cdrom':
                devices.remove(d)

        # S’assurer qu’on a un contrôleur NVMe
        nvme_ctrl = devices.find("./controller[@type='nvme']")
        if nvme_ctrl is None:
            nvme_ctrl = ET.SubElement(devices, "controller", {"type": "nvme", "index": "0"})
            # serial obligatoire pour NVMe côté libvirt récents
            ET.SubElement(nvme_ctrl, "serial").text = f"{name}-nvme0"

        # 4) Forcer UEFI/OVMF (pflash)
        ovmf = _detect_ovmf_paths()
        ovmf_code = ovmf["code"] or "/usr/share/OVMF/OVMF_CODE.fd"
        # VARS dédié à la VM (copié si besoin)
        nvram_dir = "/var/lib/libvirt/qemu/nvram"
        os.makedirs(nvram_dir, exist_ok=True)
        ovmf_vars_path = f"{nvram_dir}/{name}_VARS.fd"
        if ovmf.get("vars") and not os.path.exists(ovmf_vars_path):
            import shutil
            shutil.copyfile(ovmf["vars"], ovmf_vars_path)

        osnode = root.find('os')
        if osnode is None:
            osnode = ET.SubElement(root, 'os')
        # Nettoyer éventuels <kernel>/<initrd>/<cmdline> laissés par virt-install
        for tag in ('kernel', 'initrd', 'cmdline'):
            t = osnode.find(tag)
            if t is not None:
                osnode.remove(t)
        # Loader pflash UEFI
        # (supprime anciens <loader>/<nvram> avant d’écrire)
        for tag in ('loader', 'nvram'):
            t = osnode.find(tag)
            if t is not None:
                osnode.remove(t)
        loader = ET.SubElement(osnode, 'loader', {
            'readonly': 'yes',
            'type': 'pflash',
            'format': 'raw'
        })
        loader.text = ovmf_code
        nvram = ET.SubElement(osnode, 'nvram', {'format': 'raw'})
        nvram.text = ovmf_vars_path

        # S’assurer qu’on a bien <type machine='pc-q35-...' arch='x86_64'>hvm</type>
        type_node = osnode.find('type')
        if type_node is None:
            type_node = ET.SubElement(osnode, 'type', {'arch': 'x86_64', 'machine': 'pc-q35-6.2'})
            type_node.text = 'hvm'
        else:
            type_node.set('arch', 'x86_64')
            if 'machine' not in type_node.attrib:
                type_node.set('machine', 'pc-q35-6.2')
            type_node.text = 'hvm'

        # Optionnel : <boot dev='hd'> (conservé/ajouté)
        has_boot_hd = any(b.get('dev') == 'hd' for b in osnode.findall('boot'))
        if not has_boot_hd:
            ET.SubElement(osnode, 'boot', {'dev': 'hd'})

        # 5) Mettre l’ordre de boot sur le premier disque NVMe
        #    - on supprime les <boot order='...'> existants sur les disques
        #    - on met order='1' sur le premier nvme trouvé
        first_nvme_done = False
        for d in devices.findall("disk"):
            # virer boot order éventuel
            for b in list(d.findall('boot')):
                d.remove(b)
            tgt = d.find('target')
            if tgt is not None and tgt.get('bus') == 'nvme' and not first_nvme_done:
                ET.SubElement(d, 'boot', {'order': '1'})
                first_nvme_done = True

        # 6) CPU host-passthrough (plus simple/performant, évite qemu64 après install)
        cpu = root.find('cpu')
        if cpu is None:
            cpu = ET.SubElement(root, 'cpu')
        cpu.clear()
        cpu.set('mode', 'host-passthrough')
        cpu.set('check', 'none')
        cpu.set('migratable', 'on')

        # 7) Redéfinir la VM avec l’XML modifié
        new_xml = ET.tostring(root, encoding='unicode')
        self.conn.defineXML(new_xml)
        log_message(f"VM {name} redéfinie (post-install) sans perte de disques", "SUCCESS")

        # 8) Démarrer
        self.start_vm(name)


    def install_vm(self, vm: Dict) -> bool:
        """Installe une nouvelle VM en NVMe + UEFI proprement."""
        try:
            # Disques à créer
            if 'cloud_init' in vm:
                disks = vm['cloud_init']['user_data']['autoinstall']['storage']['disks']
            elif 'clone_init' in vm:
                disks = vm['clone_init']['user_data']['autoinstall']['storage']['disks']
            else:
                raise ValueError("Aucune config cloud_init/clone_init.")
            if not disks:
                raise ValueError("Aucun disque trouvé.")
            for d in disks:
                self._create_disk(d['path'], d.get('size', vm['disk_size']))

            # ISO cloud-init
            cloud_init_iso = self._create_init_iso(vm, 'cloud_init')

            # virt-install (UEFI + NVMe + serials + target.dev)
            cmd = [
                "virt-install",
                "--name", vm['name'],
                "--ram", str(vm['ram']),
                "--machine", "q35",
                "--vcpus", str(vm['cpu']),
                "--cpu", "qemu64",
                "--network", f"network={vm['networks'][0]['name']}",
                "--location", os.path.join(ISO_DIR, vm['cloud_init']['iso']),
                "--extra-args", "console=ttyS0,115200n8 autoinstall ds=nocloud-net",
                "--console", "pty,target_type=serial",
                "--graphics", "none",
                "--noautoconsole",
                "--controller", "type=nvme,index=0",
                "--boot", "uefi,hd,cdrom",
                "--disk", f"path={cloud_init_iso},device=cdrom,readonly=on",
            ]
            # Disques NVMe numérotés
            for i, d in enumerate(disks, start=1):
                size = d.get('size', vm['disk_size'])
                serial = d.get('serial', f"{vm['name']}-nvme0n{i}")
                target_dev = f"nvme0n{i}"
                cmd.extend([
                    "--disk",
                    f"path={d['path']},size={size},bus=nvme,serial={serial},target.bus=nvme,target.dev={target_dev}"
                ])

            print("Commande virt-install :", " ".join(cmd))
            run_command(cmd)
            return True
        except Exception as e:
            log_message(f"Erreur lors de l'installation de la VM {vm.get('name','?')}: {e}", "ERROR")
            return False

    def _update_vm_networks_libvirt(self, vm_name: str, networks: List[Dict]):
        """Remplace les interfaces réseau par celles du YAML (modèle virtio)."""
        try:
            domain = self.conn.lookupByName(vm_name)
            xml = domain.XMLDesc(0)
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml)
            # purge
            for interface in root.findall('devices/interface'):
                root.find('devices').remove(interface)
            # add
            devices = root.find('devices')
            for network in networks:
                interface = ET.SubElement(devices, 'interface', {'type': 'network'})
                ET.SubElement(interface, 'source', {'network': network['name']})
                ET.SubElement(interface, 'model', {'type': 'virtio'})
                if network.get('mac'):
                    ET.SubElement(interface, 'mac', {'address': network['mac']})
            new_xml = ET.tostring(root, encoding='unicode')
            self._safe_define_domain_xml(vm_name, new_xml)
            log_message(f"Réseaux mis à jour pour {vm_name}", "SUCCESS")
        except libvirt.libvirtError as e:
            log_message(f"Erreur réseaux {vm_name}: {e}", "ERROR")
        except Exception as e:
            log_message(f"Erreur réseaux {vm_name}: {e}", "ERROR")

    def _attach_disk_to_vm(self, vm_name: str, disk_path: str, target_dev: str = "vdb") -> bool:
        try:
            run_command([
                "virsh", "attach-disk", vm_name, disk_path,
                "--target", target_dev, "--persistent"
            ])
            log_message(f"Disque {disk_path} attaché à {vm_name}", "SUCCESS")
            return True
        except subprocess.CalledProcessError as e:
            log_message(f"Erreur attach-disk {disk_path} -> {vm_name}: {e}", "ERROR")
            return False

    def _attach_disks_to_vm(self, vm_name: str, disks: List[Dict]):
        for disk in disks:
            path = disk.get('path', '')
            if not path: continue
            target_dev = disk.get('name', 'vdb')
            self._attach_disk_to_vm(vm_name, path, target_dev)

    def _ensure_nvme_disks_defined(self, vm_name: str, disks: List[Dict]):
        """
        Après defineXML, vérifie si des disques NVMe sont présents ; sinon, les attache.
        """
        try:
            dom = self.conn.lookupByName(vm_name)
            xml = dom.XMLDesc(0)
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml)

            existing = []
            for d in root.findall("./devices/disk"):
                if d.get('device') == 'disk':
                    t = d.find('target')
                    if t is not None and t.get('bus') == 'nvme':
                        existing.append(t.get('dev'))

            if existing:
                # Déjà présents : rien à faire
                return

            # Attacher chaque disque NVMe attendu
            for i, d in enumerate(disks, start=1):
                path = d['path']
                target_dev = d.get('target_dev', f"nvme0n{i}")
                serial = d.get('serial', f"{vm_name}-nvme0n{i}")
                # --targetbus nvme pour s'assurer du bus
                cmd = [
                    "virsh", "attach-disk", vm_name, path, target_dev,
                    "--targetbus", "nvme",
                    "--driver", "qemu",
                    "--subdriver", "qcow2",
                    "--serial", serial,
                    "--config"
                ]
                run_command(cmd, show_output=False)
                log_message(f"Disque NVMe attaché: {path} -> {target_dev}", "SUCCESS")

        except subprocess.CalledProcessError as e:
            log_message(f"Erreur attach-disk NVMe {vm_name}: {e}", "ERROR")
            raise
        except Exception as e:
            log_message(f"Erreur _ensure_nvme_disks_defined: {e}", "ERROR")
            raise



    def _clone_vm(self, source_vm_name: str, target_vm: Dict) -> bool:
        """
        Clonage sans virt-clone:
        - arrêt source
        - création overlay + data
        - génération ISO clone_init
        - définition du domaine (disques + cdrom intégrés)
        - démarrage
        """
        name = target_vm['name']
        try:
            if not self._shutdown_domain(source_vm_name, timeout=180):
                log_message(f"Impossible d'arrêter {source_vm_name}.", "ERROR")
                return False

            src_disks = self._read_source_disk_paths(source_vm_name)
            created_disks = self._create_clone_disks(src_disks, target_vm)
            target_vm["_created_disks"] = created_disks

            clone_iso = self._create_init_iso(target_vm, 'clone_init')
            target_vm["_clone_iso"] = clone_iso

            self._define_clone_domain(target_vm)

            # plus besoin d’attacher l’ISO ou de re-attacher disques ici :
            # ils sont déjà dans le XML rendu par le template

            self.start_vm(name)
            log_message(f"VM {name} clonée et démarrée.", "SUCCESS")
            return True
        except Exception as e:
            log_message(f"Erreur lors du clonage de {name}: {e}", "ERROR")
            return False


    def clone_vm(self, source_vm_name: str, target_vm: Dict) -> bool:
        """
        Orchestration de clonage sans virt-clone : qemu-img + template + change-media.
        """
        ok = self._clone_vm(source_vm_name, target_vm)
        if not ok:
            return False

        # # Resize “online” au besoin (si tu as des règles de resize via agent / cloud-init)
        # disks = target_vm['clone_init']['user_data']['autoinstall']['storage'].get('disks', [])
        # for d in disks:
        #     if d.get('resize', False):
        #         # NOTE : _resize_disk() attend un path fichier de bloc (virsh blockresize).
        #         # Ici on vient de créer le qcow2 à la bonne taille, donc pas forcément utile.
        #         # Tu peux conserver si tu relies à un workflow existant.
        #         try:
        #             self._resize_disk(target_vm, d['path'])
        #         except Exception:
        #             pass
        return True




    def _normalize_boot_xml(self, name: str) -> None:
        """
        Supprime tout ordre de boot conflictuel :
        - enlève <boot .../> dans *tous* les périphériques
        - enlève *tous* les <os><boot .../></os> et <os><bootmenu .../>
        - conserve <os>/<type>, <loader>, <nvram>
        - ajoute un contrôleur SATA si absent (pour CD-ROM)
        Redéfinit le domaine si des changements ont été faits.
        """
        import xml.etree.ElementTree as ET

        dom = self.conn.lookupByName(name)
        xml = dom.XMLDesc(0)
        root = ET.fromstring(xml)

        changed = False

        # -- devices: remove per-device <boot .../>
        devices = root.find("./devices")
        if devices is not None:
            for elem in list(devices):
                boot = elem.find("boot")
                if boot is not None:
                    elem.remove(boot)
                    changed = True

            # ensure we have a SATA controller for cdrom ops
            if devices.find("./controller[@type='sata']") is None:
                ET.SubElement(devices, "controller", {"type": "sata", "index": "0"})
                changed = True

        # -- os: remove <boot .../> and <bootmenu .../>
        osnode = root.find("./os")
        if osnode is not None:
            removed = False
            for boot in list(osnode.findall("boot")):
                osnode.remove(boot)
                removed = True
            bm = osnode.find("bootmenu")
            if bm is not None:
                osnode.remove(bm)
                removed = True
            if removed:
                changed = True

        if changed:
            new_xml = ET.tostring(root, encoding="unicode")
            self.conn.defineXML(new_xml)







    def _find_cdrom_target(self, name: str) -> Optional[str]:
        """Return target dev of an existing CD-ROM (e.g. 'sda'/'sdb'), else None."""
        import xml.etree.ElementTree as ET
        dom = self.conn.lookupByName(name)
        xml = dom.XMLDesc(0)
        root = ET.fromstring(xml)
        for cd in root.findall("./devices/disk[@device='cdrom']"):
            tgt = cd.find("target")
            if tgt is not None and tgt.get("dev"):
                return tgt.get("dev")
        return None









    # --- Helpers clonage -------------------------------------------------

    def _shutdown_domain(self, name: str, timeout: int = 180) -> bool:
        """Shutdown propre d'un domaine, fallback destroy si nécessaire."""
        try:
            domain = self.conn.lookupByName(name)
        except libvirt.libvirtError:
            log_message(f"VM source {name} introuvable", "ERROR")
            return False

        try:
            if domain.isActive():
                log_message(f"Arrêt propre de la VM source {name}...", "INFO")
                try:
                    domain.shutdown()
                except libvirt.libvirtError:
                    log_message("shutdown() failed, will try virsh shutdown", "WARNING")
                    run_command(["virsh", "shutdown", name], show_output=False, check=False)

                # wait
                start = time.time()
                while domain.isActive():
                    if time.time() - start > timeout:
                        log_message(f"Timeout arrêt {name}, destruction forcée...", "WARNING")
                        try:
                            domain.destroy()
                        except libvirt.libvirtError as e:
                            log_message(f"Impossible de détruire {name}: {e}", "ERROR")
                            return False
                        break
                    time.sleep(1)
            return True
        except Exception as e:
            log_message(f"Erreur en arrêtant {name}: {e}", "ERROR")
            return False

    
    def _read_source_disk_paths(self, source_vm_name: str) -> list:
        """
        Lit les disques 'device=disk' de la VM source (ordre XML).
        Retourne une liste de chemins absolus (qcow2) du/ des disques système.
        """
        dom = self.conn.lookupByName(source_vm_name)
        import xml.etree.ElementTree as ET
        root = ET.fromstring(dom.XMLDesc(0))
        paths = []
        for d in root.findall("./devices/disk[@device='disk']"):
            src = d.find("source")
            if src is not None and 'file' in src.attrib:
                paths.append(src.attrib['file'])
        if not paths:
            raise RuntimeError(f"Aucun disque 'device=disk' trouvé sur {source_vm_name}")
        return paths



    def _create_clone_disks(self, source_paths: list, target_vm: Dict) -> list:
        """
        Crée les disques du clone:
        - overlay système (backing=source qcow2) + taille désirée
        - disques data (qcow2 neufs)
        Retourne une liste [{path, bus, target_dev, serial}, ...] avec UN SEUL serial partagé (nvme).
        """
        created = []

        storage = target_vm['clone_init']['user_data']['autoinstall']['storage']
        disks_yaml = storage.get('disks', [])
        if not disks_yaml:
            raise RuntimeError(f"Aucun disque défini dans le YAML pour {target_vm['name']}")

        # Serial commun pour contrôleur + disques NVMe
        nvme_serial = f"{target_vm['name']}-nvme0"

        # 1) Disque système (overlay)
        sys_disk = disks_yaml[0]
        sys_path = sys_disk['path']
        sys_size = str(sys_disk.get('size', target_vm.get('disk_size', 20))) + "G"
        if not os.path.exists(sys_path):
            run_command([
                "qemu-img", "create", "-f", "qcow2",
                "-F", "qcow2", "-b", source_paths[0],
                sys_path, sys_size
            ], show_output=False)
            log_message(f"[CLONE] Overlay système créé: {sys_path} (base={source_paths[0]}, size={sys_size})", "SUCCESS")
        else:
            log_message(f"[CLONE] Overlay système existe déjà: {sys_path}", "WARNING")

        created.append({
            "path": sys_path,
            "bus": "nvme",
            "target_dev": "nvme0n1",
            "serial": nvme_serial,       # <- même serial que le contrôleur
        })

        # 2) Disques data (index >= 1)
        nv_idx = 2
        for d in disks_yaml[1:]:
            data_path = d['path']
            data_size = str(d.get('size', 10)) + "G"
            if not os.path.exists(data_path):
                run_command(["qemu-img", "create", "-f", "qcow2", data_path, data_size], show_output=False)
                log_message(f"[CLONE] Disque data créé: {data_path} ({data_size})", "SUCCESS")
            else:
                log_message(f"[CLONE] Disque data existe déjà: {data_path}", "WARNING")
            created.append({
                "path": data_path,
                "bus": "nvme",
                "target_dev": f"nvme0n{nv_idx}",
                "serial": nvme_serial,    # <- identique
            })
            nv_idx += 1

        # stocker le serial contrôleur pour le template
        target_vm["_nvme_controller_serial"] = nvme_serial
        return created


    def _define_clone_domain(self, target_vm: Dict) -> None:
        ovmf = _detect_ovmf_paths()
        vm = dict(target_vm)
        vm["ovmf_code"] = ovmf["code"] or "/usr/share/OVMF/OVMF_CODE.fd"
        vm["ovmf_vars_path"] = f"/var/lib/libvirt/qemu/nvram/{vm['name']}_VARS.fd"
        os.makedirs("/var/lib/libvirt/qemu/nvram", exist_ok=True)
        if ovmf["vars"] and not os.path.exists(vm["ovmf_vars_path"]):
            import shutil
            shutil.copyfile(ovmf["vars"], vm["ovmf_vars_path"])

        vm["disks"] = target_vm.get("_created_disks", [])
        vm["cdroms"] = []
        clone_iso = target_vm.get("_clone_iso")
        if clone_iso:
            vm["cdroms"].append({"path": clone_iso, "bus": "sata", "target_dev": "sda"})

        # <- injecter le serial contrôleur commun
        vm["nvme_controller_serial"] = target_vm.get("_nvme_controller_serial", f"{vm['name']}-nvme0")

        template = env.get_template('vm.xml.j2')
        vm_xml = template.render(vm=vm)
        self.conn.defineXML(vm_xml)
        log_message(f"VM {vm['name']} définie via template (NVMe/UEFI)", "SUCCESS")



    def _ensure_cdrom_and_insert_iso(self, vm_name: str, iso_path: str, target_dev: str = "sda") -> bool:
        """
        Essaye d'insérer l'ISO sur le device cdrom existant (par ex sda).
        Si plusieurs cdroms, on teste chacun jusqu'à succès.
        """
        try:
            dom = self.conn.lookupByName(vm_name)
            xml = dom.XMLDesc(0)
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml)
            # find cdrom disk device names
            cdrom_targets = []
            for d in root.findall("./devices/disk"):
                if d.get('device') == 'cdrom':
                    t = d.find('target')
                    if t is not None and t.get('dev'):
                        cdrom_targets.append(t.get('dev'))

            if not cdrom_targets:
                log_message(f"Aucun cdrom présent dans {vm_name} pour insertion ISO", "ERROR")
                return False

            # essayer change-media sur chaque target
            for tgt in cdrom_targets:
                try:
                    run_command(['virsh', 'change-media', vm_name, tgt, '--insert', iso_path, '--config', '--force'], show_output=False)
                    log_message(f"ISO insérée via change-media sur {vm_name} ({tgt})", "SUCCESS")
                    return True
                except subprocess.CalledProcessError:
                    # essayer le suivant
                    continue

            log_message(f"Impossible d'insérer l'ISO {iso_path} sur les cdroms de {vm_name}", "ERROR")
            return False

        except libvirt.libvirtError as e:
            log_message(f"Erreur accessing domain {vm_name} pour insertion ISO: {e}", "ERROR")
            return False
        except Exception as e:
            log_message(f"Erreur insertion ISO: {e}", "ERROR")
            return False














    def _vm_xml(self, name: str) -> str:
        return self.conn.lookupByName(name).XMLDesc(0)

    def _ensure_sata_controller(self, name: str) -> None:
        """Ajoute un contrôleur SATA si absent (utile pour un cdrom sda/sdb)."""
        import xml.etree.ElementTree as ET
        xml = self._vm_xml(name)
        root = ET.fromstring(xml)
        if root.find("./devices/controller[@type='sata']") is not None:
            return  # déjà présent
        # Ajout persisté (domain éteint de préférence)
        attach_xml = "<controller type='sata' index='0'/>"
        subprocess.run(
            ["bash","-lc", f"cat <<'XML' | virsh attach-device {name} --config\n{attach_xml}\nXML"],
            check=True
        )
        log_message(f"Contrôleur SATA ajouté sur {name}", "SUCCESS")

    def _pick_free_sata_target(self, name: str) -> str:
        """Choisit sda/sdb/sdc... libre pour le cdrom."""
        import xml.etree.ElementTree as ET
        used = set()
        root = ET.fromstring(self._vm_xml(name))
        for t in root.findall("./devices/disk[@device='cdrom']/target[@bus='sata']"):
            dev = t.get("dev")
            if dev and dev.startswith("sd"):
                used.add(dev)
        for c in "abcdefghijklmnopqrstuvwxyz":
            cand = f"sd{c}"
            if cand not in used:
                return cand
        return "sda"

    def _attach_config_iso(self, name: str, iso_path: str, live: bool = False) -> str:
        """
        Attache l'ISO de config comme cdrom SATA en readonly (pas de boot order modifié).
        Retourne le target (ex: 'sda') utilisé.
        """
        self._ensure_sata_controller(name)
        target = self._pick_free_sata_target(name)
        cmd = [
            "virsh", "attach-disk", name, iso_path, target,
            "--type", "cdrom", "--mode", "readonly", "--config"
        ]
        if live:
            cmd.append("--live")
        run_command(cmd, check=True)
        log_message(f"ISO attachée à {name}:{target} -> {iso_path}", "SUCCESS")
        return target

    def _eject_config_iso(self, name: str, iso_path: str) -> None:
        """Éjecte/détache le lecteur cdrom qui pointe sur iso_path (si présent)."""
        import xml.etree.ElementTree as ET
        root = ET.fromstring(self._vm_xml(name))
        for cd in root.findall("./devices/disk[@device='cdrom']"):
            src = cd.find("source")
            tgt = cd.find("target")
            if src is not None and src.get("file") == iso_path and tgt is not None:
                dev = tgt.get("dev")
                if dev:
                    # éjecter puis détacher
                    run_command(["virsh","change-media",name,dev,"--eject","--config","--force"], check=False)
                    run_command(["virsh","detach-disk",name,dev,"--config"], check=False)
                    log_message(f"ISO éjectée et lecteur retiré {name}:{dev}", "SUCCESS")
                return








    def _attach_iso_to_vm(self, vm_name: str, iso_path: str) -> bool:
        """Attache/insère une ISO en CD-ROM via change-media, en neutralisant tout conflit de boot."""
        try:
            # 1) normaliser toujours avant
            self._normalize_boot_xml(vm_name)

            # 2) trouver une cible cdrom (sda/sr0), sinon créer sda via attach-disk cdrom
            xml = self.conn.lookupByName(vm_name).XMLDesc(0)
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml)
            devices = root.find("./devices")
            targetdev = None
            if devices is not None:
                for cd in devices.findall("./disk[@device='cdrom']"):
                    tgt = cd.find("target")
                    if tgt is not None and tgt.get("dev"):
                        targetdev = tgt.get("dev")
                        break
            if targetdev is None:
                # créer un cdrom SATA vide pour avoir une cible stable
                run_command([
                    "virsh","attach-disk", vm_name, "/dev/null",
                    "--type","cdrom","--target","sda","--config"
                ], check=False)
                targetdev = "sda"

            # 3) insertion
            try:
                run_command([
                    "virsh","change-media", vm_name, targetdev,
                    "--insert", iso_path, "--config", "--force"
                ], check=True)
                log_message(f"ISO insérée via change-media sur {vm_name} ({targetdev})", "SUCCESS")
                return True
            except subprocess.CalledProcessError as e:
                err = str(e)
                if "éléments de démarrage par périphérique" in err or "boot" in err.lower():
                    # retry après purge *spectaculaire*
                    self._normalize_boot_xml(vm_name)
                    run_command([
                        "virsh","change-media", vm_name, targetdev,
                        "--insert", iso_path, "--config", "--force"
                    ], check=True)
                    log_message(f"ISO insérée (retry) via change-media sur {vm_name} ({targetdev})", "SUCCESS")
                    return True
                raise
        except Exception as e:
            log_message(f"Erreur attachement ISO à {vm_name}: {e}", "ERROR")
            return False



    # def _resize_disk(self, vm: Dict, disk_path: str = None) -> bool:
    #     try:
    #         disks = []
    #         if 'cloud_init' in vm:
    #             disks = vm['cloud_init']['user_data']['autoinstall'].get('storage', {}).get('disks', []) \
    #                     or vm['cloud_init']['user_data']['autoinstall'].get('disks', [])
    #         elif 'clone_init' in vm:
    #             disks = vm['clone_init']['user_data']['autoinstall'].get('storage', {}).get('disks', [])

    #         if not disks:
    #             log_message(f"Aucun disque pour {vm['name']}", "ERROR")
    #             return False

    #         if disk_path is None:
    #             disk_path = disks[0]['path']

    #         target_disk = next((d for d in disks if d['path'] == disk_path), None)
    #         if not target_disk:
    #             log_message(f"Disque {disk_path} non trouvé", "ERROR")
    #             return False

    #         resize_config = target_disk.get('resize_config', {})
    #         if not resize_config.get('enable', False):
    #             log_message(f"Redimensionnement désactivé pour {disk_path}", "INFO")
    #             return True

    #         new_size_gb = target_disk.get('size', vm['disk_size'])
    #         run_command(["virsh", "blockresize", vm['name'], "--path", disk_path, "--size", f"{new_size_gb}G"])
    #         log_message(f"Disque {disk_path} agrandi à {new_size_gb}G", "SUCCESS")
    #         return True
    #     except subprocess.CalledProcessError as e:
    #         log_message(f"Erreur blockresize {vm['name']}: {e}", "ERROR")
    #         return False

    def wait_for_vm_shutdown(self, name: str, timeout: int = 3000, interval: int = 1) -> bool:
        start_time = time.time()
        log_message(f"Attente de l'extinction de la VM {name}...", "INFO")
        while True:
            domain = self.conn.lookupByName(name)
            if not domain.isActive():
                log_message(f"VM {name} est éteinte !", "SUCCESS")
                return True
            if time.time() - start_time > timeout:
                log_message(f"Timeout atteint après {timeout} secondes pour {name}.", "ERROR")
                return False
            time.sleep(interval)

    def start_vm(self, name: str):
        try:
            domain = self.conn.lookupByName(name)
            if domain.isActive():
                log_message(f"VM {name} est déjà démarrée", "WARNING"); return
            domain.create()
            log_message(f"VM {name} démarrée", "SUCCESS")
        except libvirt.libvirtError as e:
            log_message(f"Erreur démarrage VM {name}: {e}", "ERROR")
            raise

    def execute_via_qemu_agent(self, vm_name: str, command, username: str = "root", wait_for_completion: bool = True, timeout: int = 30) -> Dict:
        try:
            internal = {"guest-ping","guest-sync","guest-get-users","guest-exec-status","guest-info","guest-get-fsinfo",
                        "guest-get-disks","guest-network-get-interfaces","guest-file-open","guest-file-write","guest-file-close"}
            if isinstance(command, dict) and command.get("execute") in internal:
                command_dict = command
            elif isinstance(command, str) and command in internal:
                command_dict = {"execute": command}
            else:
                if isinstance(command, str):
                    parts = command.split()
                    path = parts[0]; args = parts[1:] if len(parts) > 1 else []
                    command_dict = {"execute":"guest-exec","arguments":{"path":path,"arg":args,"capture-output":True}}
                elif isinstance(command, dict):
                    command_dict = command
                else:
                    raise ValueError("La commande doit être une chaîne ou un dict")

            cmd = ["virsh","qemu-agent-command",vm_name,json.dumps(command_dict)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if result.returncode != 0:
                return {'success': False,'output': None,'error': f"Erreur commande: {result.stderr}",'pid': None}
            try:
                output = json.loads(result.stdout)
            except json.JSONDecodeError:
                return {'success': False,'output': None,'error': f"Réponse invalide: {result.stdout}",'pid': None}

            if command_dict.get("execute") == "guest-exec" and 'return' in output and 'pid' in output['return'] and wait_for_completion:
                pid = output['return']['pid']
                while True:
                    time.sleep(1)
                    status_cmd = {"execute":"guest-exec-status","arguments":{"pid":pid}}
                    status_result = subprocess.run(
                        ["virsh","qemu-agent-command",vm_name,json.dumps(status_cmd)],
                        capture_output=True, text=True, timeout=10
                    )
                    if status_result.returncode != 0:
                        continue
                    try:
                        status_output = json.loads(status_result.stdout)
                        if status_output.get('return', {}).get('exited', False):
                            return {'success': True,'output': status_output,'error': None,'pid': pid}
                    except json.JSONDecodeError:
                        continue
            elif 'return' in output:
                return {'success': True,'output': output,'error': None,'pid': None}
            return {'success': False,'output': output,'error': "Résultat invalide",'pid': None}
        except subprocess.TimeoutExpired:
            return {'success': False,'output': None,'error': "Timeout atteint après 30s",'pid': None}
        except Exception as e:
            return {'success': False,'output': None,'error': str(e),'pid': None}

    def wait_for_agent(self, vm_name: str, timeout: int = 600) -> bool:
        start_time = time.time()
        while time.time() - start_time < timeout:
            log_message("Waiting for agent...", "INFO")
            result = self.execute_via_qemu_agent(vm_name, "guest-ping")
            if result['success'] and result['output'].get('return') == {}:
                log_message("Agent QEMU disponible !", "SUCCESS")
                return True
            if result['error'] and "not configured" in result['error']:
                log_message(f"Le canal QEMU Guest Agent n'est pas configuré pour {vm_name}", "ERROR")
                return False
            time.sleep(1)
        log_message(f"Timeout atteint pour l'agent QEMU de {vm_name}", "ERROR")
        return False

    def copy_files_via_agent(self, vm: Dict):
        if not self.wait_for_agent(vm['name']):
            log_message(f"Échec de la connexion à l'agent QEMU pour {vm['name']}", "ERROR")
            return
        if 'copy_files' not in vm:
            return
        for file_item in vm['copy_files']:
            source_path = os.path.join(FILES_DIR, file_item['source'])
            if not os.path.exists(source_path):
                log_message(f"Source introuvable: {source_path}", "ERROR")
                continue
            dest_path = file_item['destination']
            if os.path.isdir(source_path):
                self._copy_directory_via_agent(vm['name'], source_path, dest_path)
            else:
                self._copy_file_via_agent(vm['name'], source_path, dest_path)

    def _create_directory_via_agent(self, vm_name: str, path: str) -> bool:
        path = os.path.normpath(path)
        if not path.startswith('/'): path = '/' + path
        result = self.execute_via_qemu_agent(vm_name, f"/bin/mkdir -p {path}")
        if result['success']:
            log_message(f"Répertoire {path} créé dans {vm_name}", "SUCCESS"); return True
        log_message(f"Erreur création répertoire {path}: {result['error']}", "ERROR"); return False

    def _copy_file_via_agent(self, vm_name: str, source_path: str, dest_path: str) -> bool:
        try:
            dest_dir = os.path.dirname(dest_path)
            if dest_dir and dest_dir != '/' and not self._create_directory_via_agent(vm_name, dest_dir):
                return False
            with open(source_path, 'rb') as f:
                content = f.read()
            content_b64 = base64.b64encode(content).decode('utf-8')
            open_cmd = {"execute": "guest-file-open","arguments": {"path": dest_path,"mode": "w"}}
            open_result = self.execute_via_qemu_agent(vm_name, open_cmd)
            if not open_result['success']:
                log_message(f"Erreur open {dest_path}: {open_result['error']}", "ERROR"); return False
            fh = open_result['output']['return']
            try:
                chunk_size = 4 * 1024 * 1024
                for i in range(0, len(content_b64), chunk_size):
                    chunk = content_b64[i:i+chunk_size]
                    write_cmd = {"execute": "guest-file-write","arguments": {"handle": fh,"buf-b64": chunk}}
                    write_result = self.execute_via_qemu_agent(vm_name, write_cmd)
                    if not write_result['success']:
                        log_message(f"Erreur write {dest_path}: {write_result['error']}", "ERROR"); return False
                log_message(f"Fichier {source_path} copié vers {dest_path}", "SUCCESS")
                return True
            finally:
                self.execute_via_qemu_agent(vm_name, {"execute":"guest-file-close","arguments":{"handle": fh}})
        except Exception as e:
            log_message(f"Erreur copie fichier {source_path}: {e}", "ERROR"); return False

    def _write_file_via_agent(self, vm_name: str, dest_path: str, content_b64: str) -> bool:
        dest_dir = os.path.dirname(dest_path)
        if dest_dir and dest_dir != '/' and not self._create_directory_via_agent(vm_name, dest_dir):
            log_message(f"Échec création parent {dest_dir}", "ERROR"); return False
        open_cmd = {"execute": "guest-file-open","arguments": {"path": dest_path,"mode": "w"}}
        open_result = self.execute_via_qemu_agent(vm_name, open_cmd)
        if not open_result['success']:
            log_message(f"Échec open {dest_path}: {open_result['error']}", "ERROR"); return False
        fh = open_result['output']['return']
        try:
            chunk_size = 4 * 1024 * 1024
            for i in range(0, len(content_b64), chunk_size):
                chunk = content_b64[i:i+chunk_size]
                write_cmd = {"execute":"guest-file-write","arguments":{"handle":fh,"buf-b64":chunk}}
                write_result = self.execute_via_qemu_agent(vm_name, write_cmd)
                if not write_result['success']:
                    log_message(f"Échec écriture {dest_path}: {write_result['error']}", "ERROR"); return False
            return True
        finally:
            self.execute_via_qemu_agent(vm_name, {"execute":"guest-file-close","arguments":{"handle":fh}})

    def _copy_directory_via_agent(self, vm_name: str, source_dir: str, dest_dir: str) -> bool:
        try:
            source_dir = os.path.normpath(source_dir)
            dest_dir = os.path.normpath(dest_dir)
            if not os.path.exists(source_dir):
                log_message(f"Répertoire source {source_dir} introuvable", "ERROR"); return False
            tar_path = "/tmp/copy_dir.tar.gz"
            parent_dir = os.path.dirname(source_dir)
            dir_name = os.path.basename(source_dir)
            subprocess.run(["tar","czf",tar_path,"-C",parent_dir,dir_name], check=True)
            with open(tar_path, 'rb') as f:
                tar_content_b64 = base64.b64encode(f.read()).decode('utf-8')
            if not self._create_directory_via_agent(vm_name, dest_dir): return False
            archive_dest = f"{dest_dir}/archive.tar.gz"
            if not self._write_file_via_agent(vm_name, archive_dest, tar_content_b64): return False
            if not self.execute_via_qemu_agent(vm_name, f"/bin/tar xzf {archive_dest} -C {dest_dir}")['success']:
                log_message("Erreur extraction archive", "ERROR"); return False
            self.execute_via_qemu_agent(vm_name, f"/bin/rm -f {archive_dest}")
            log_message(f"Répertoire {source_dir} copié vers {dest_dir}", "SUCCESS")
            return True
        except subprocess.CalledProcessError as e:
            log_message(f"Erreur création archive: {e}", "ERROR"); return False
        except Exception as e:
            log_message(f"Erreur copie répertoire {source_dir}: {e}", "ERROR"); return False
        finally:
            try:
                if os.path.exists("/tmp/copy_dir.tar.gz"):
                    os.remove("/tmp/copy_dir.tar.gz")
            except: pass

    def run_scripts_via_agent(self, vm: Dict):
        if not self.wait_for_agent(vm['name']):
            log_message(f"Échec de la connexion à l'agent QEMU pour {vm['name']}", "ERROR"); return
        if 'post_install_scripts' not in vm:
            log_message(f"Aucun script à exécuter pour {vm['name']}", "WARNING"); return
        for script in vm['post_install_scripts']:
            script_path = os.path.join(SCRIPTS_DIR, script)
            if not os.path.exists(script_path):
                log_message(f"Script introuvable: {script_path}", "ERROR"); continue
            script_dest = f"/tmp/{os.path.basename(script_path)}"
            with open(script_path, 'rb') as f:
                script_b64 = base64.b64encode(f.read()).decode('utf-8')
            if not self._write_file_via_agent(vm['name'], script_dest, script_b64):
                log_message(f"Échec écriture script {script} dans {vm['name']}", "ERROR"); continue
            if not self.execute_via_qemu_agent(vm['name'], {"execute":"guest-exec","arguments":{"path":"/bin/chmod","arg":["+x",script_dest],"capture-output":True}})['success']:
                log_message(f"chmod échoué {script_dest}", "ERROR"); continue
            if self.execute_via_qemu_agent(vm['name'], {"execute":"guest-exec","arguments":{"path":script_dest,"capture-output":True}})['success']:
                log_message(f"Script {script} exécuté", "SUCCESS")
            else:
                log_message(f"Erreur exécution script {script}", "ERROR")


    def deploy_vm(self, vm, conn_lock):
        try:
            with conn_lock:
                self.conn = libvirt.open("qemu:///system")

            if not self.vm_exists(vm['name']):
                log_message(f"{vm['name']} n'existe pas (install/clonage a échoué). On saute.", "WARNING")
                return

            log_message(f"Déploiement de la VM {vm['name']}...", "INFO")

            # À partir d'ici, elle existe (install/clone). Pas de redéfinition au template.
            # ... (attentes agent, copies, scripts, etc.)
            # Démarrer si pas actif
            self.start_vm(vm['name'])

            if 'clone_init' in vm:
                if not self.wait_for_agent(vm['name']):
                    log_message(f"Timeout qemu-guest-agent {vm['name']}", "ERROR")
                    return
                self.apply_clone_init_via_agent(vm)
                self.run_configure_vm_script(vm['name'])

            self.copy_files_via_agent(vm)
            self.run_scripts_via_agent(vm)

        except Exception as e:
            log_message(f"Erreur lors du déploiement de la VM {vm['name']}: {e}", "ERROR")



    def deploy_vms(self):
        # Étape 1: install / clone
        created_or_existing = []
        for vm in self.infra['vms']:
            if self.vm_exists(vm['name']):
                created_or_existing.append(vm)
                continue

            if 'cloud_init' in vm:
                if self.install_vm(vm):
                    self.finalize_vm_post_install(vm)
                    created_or_existing.append(vm)
                else:
                    log_message(f"Échec de l'installation de {vm['name']}", "ERROR")

            elif 'clone_init' in vm:
                src = vm['clone_init']['source_vm']
                if self.clone_vm(src, vm):
                    created_or_existing.append(vm)
                else:
                    log_message(f"Échec du clonage {vm['name']}", "ERROR")
            else:
                log_message(f"{vm['name']}: ni cloud_init ni clone_init", "ERROR")

        # Étape 2: uniquement pour celles qui existent vraiment
        conn_lock = threading.Lock()
        threads = []
        for vm in created_or_existing:
            thread = threading.Thread(target=self.deploy_vm, args=(vm, conn_lock))
            threads.append(thread)
            thread.start()

        for t in threads:
            t.join()




    def run_configure_vm_script(self, vm_name: str) -> bool:
        configure_vm_script = os.path.join(SCRIPTS_DIR, "clone/configure_vm.py")
        if not os.path.exists(configure_vm_script):
            log_message(f"Script configure_vm introuvable: {configure_vm_script}", "ERROR"); return False
        log_message(f"Exécution configure_vm sur {vm_name}", "INFO")
        script_dest = f"/tmp/configure_vm.py"
        try:
            with open(configure_vm_script, 'rb') as f:
                script_b64 = base64.b64encode(f.read()).decode('utf-8')
            if not self._write_file_via_agent(vm_name, script_dest, script_b64):
                log_message(f"Échec écriture configure_vm dans {vm_name}", "ERROR"); return False
            if not self.execute_via_qemu_agent(vm_name, {"execute":"guest-exec","arguments":{"path":"/bin/chmod","arg":["+x",script_dest],"capture-output":True}})['success']:
                log_message(f"chmod échoué {script_dest}", "ERROR"); return False
            if not self.execute_via_qemu_agent(vm_name, "/bin/mkdir -p /mnt")['success']:
                log_message("Échec création /mnt", "ERROR"); return False
            if not self.execute_via_qemu_agent(vm_name, "/bin/mount /dev/sr0 /mnt")['success']:
                log_message("Échec montage ISO", "ERROR"); return False
            if self.execute_via_qemu_agent(vm_name, {"execute":"guest-exec","arguments":{"path":script_dest,"capture-output":True}})['success']:
                log_message("configure_vm exécuté", "SUCCESS"); return True
            log_message("Erreur exécution configure_vm", "ERROR"); return False
        except Exception as e:
            log_message(f"Erreur configure_vm: {e}", "ERROR"); return False

    def _create_init_iso(self, vm: Dict, init_type: str) -> str:
        meta_data = ""
        user_data_str = ""
        if init_type == 'cloud_init':
            meta_data = "\n".join(f"{k}: {v}" for k, v in vm.get('cloud_init', {}).get('meta_data', {}).items())
            user_data = vm.get('cloud_init', {}).get('user_data', {})
            user_data_str = "#cloud-config\n" + yaml.dump(user_data, default_flow_style=False, sort_keys=False)
        elif init_type == 'clone_init':
            meta_data = "\n".join(f"{k}: {v}" for k, v in vm.get('clone_init', {}).get('meta_data', {}).items())
            user_data = vm.get('clone_init', {}).get('user_data', {})
            user_data_str = "#cloud-config\n" + yaml.dump(user_data, default_flow_style=False, sort_keys=False)
        else:
            log_message(f"Type d'initialisation inconnu: {init_type}", "ERROR")
            return None

        with open("/tmp/meta-data", "w") as f: f.write(meta_data)
        with open("/tmp/user-data", "w") as f: f.write(user_data_str)

        os.makedirs(CLOUD_INIT_ISO_DIR, exist_ok=True)
        iso_path = os.path.join(CLOUD_INIT_ISO_DIR, f"{vm['name']}-{init_type}.iso")
        run_command(['genisoimage','-input-charset','utf-8','-output',iso_path,'-volid','cidata','-joliet','-rock','/tmp/meta-data','/tmp/user-data'])
        log_message(f"ISO {init_type} générée: {iso_path}", "SUCCESS")
        return iso_path

    def _create_disk(self, path: str, size_gb: int):
        if os.path.exists(path):
            log_message(f"Disque {path} existe déjà, ignoré", "WARNING"); return
        run_command(['qemu-img','create','-f','qcow2',path,f"{size_gb}G"])
        log_message(f"Disque {path} créé ({size_gb} Go)", "SUCCESS")

    def deploy_firewall(self):
        if 'firewall' not in self.infra: return
        log_message("Règles de pare-feu à appliquer manuellement:", "INFO")
        for rule in self.infra['firewall']['rules']:
            action = "AUTHORISER" if rule['action'] == "allow" else "REFUSER"
            log_message(f"{action} {rule['protocol']}/{rule['port']} vers {rule['vm']} depuis {rule['source']}", "INFO")

    def clean(self):
        log_message(f"Nettoyage de l'infrastructure {self.infra['name']}...", "INFO")
        for vm in self.infra['vms']:
            self._clean_vm(vm)
        for network in reversed(self.infra.get('networks', [])):
            self._clean_network(network)
        log_message("Nettoyage terminé !", "SUCCESS")

    def _clean_vm(self, vm: Dict):
        """Suppression UEFI-safe (NVRAM incluse) + disques + ISO."""
        name = vm['name']
        log_message(f"Suppression de la VM {name}...", "INFO")
        try:
            domain = self.conn.lookupByName(name)
        except libvirt.libvirtError:
            log_message(f"VM {name} non trouvée", "WARNING")
            return

        try:
            if domain.isActive():
                domain.destroy()
                log_message(f"VM {name} arrêtée", "SUCCESS")
        except libvirt.libvirtError as e:
            log_message(f"Erreur arrêt VM {name}: {e}", "ERROR")

        nvram_path = None
        try:
            xml = domain.XMLDesc(0)
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml)
            nv = root.find('./os/nvram')
            if nv is not None and nv.text:
                nvram_path = nv.text.strip()
        except Exception:
            pass

        flags = 0
        for attr in [
            'VIR_DOMAIN_UNDEFINE_MANAGED_SAVE',
            'VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA',
            'VIR_DOMAIN_UNDEFINE_CHECKPOINTS_METADATA',
            'VIR_DOMAIN_UNDEFINE_NVRAM',
        ]:
            flags |= getattr(libvirt, attr, 0)

        try:
            if flags:
                domain.undefineFlags(flags)
            else:
                domain.undefine()
            log_message(f"Définition de VM {name} supprimée", "SUCCESS")
        except libvirt.libvirtError as e:
            log_message(f"undefineFlags() échoué: {e}", "WARNING")
            try:
                run_command(['virsh','undefine',name,'--nvram','--managed-save','--snapshots-metadata','--checkpoints-metadata'], check=True)
                log_message(f"virsh undefine --nvram OK pour {name}", "SUCCESS")
            except Exception as e2:
                log_message(f"virsh undefine fallback échoué: {e2}", "ERROR")
                try:
                    domain.undefine()
                    log_message(f"undefine() simple OK pour {name}", "SUCCESS")
                except libvirt.libvirtError as e3:
                    log_message(f"Impossible de supprimer la définition {name}: {e3}", "ERROR")

        if nvram_path:
            try:
                if os.path.exists(nvram_path):
                    os.remove(nvram_path)
                    log_message(f"NVRAM supprimée: {nvram_path}", "SUCCESS")
            except Exception as e:
                log_message(f"Impossible de supprimer NVRAM {nvram_path}: {e}", "WARNING")

        # Disques data d’après YAML
        disks = []
        if 'cloud_init' in vm:
            disks = vm['cloud_init']['user_data']['autoinstall'].get('storage', {}).get('disks', []) \
                    or vm['cloud_init']['user_data']['autoinstall'].get('disks', [])
        elif 'clone_init' in vm:
            disks = vm['clone_init']['user_data']['autoinstall'].get('storage', {}).get('disks', [])
        for d in disks or []:
            path = d.get('path'); 
            if not path: continue
            try:
                if os.path.exists(path):
                    os.remove(path)
                    log_message(f"Disque {path} supprimé", "SUCCESS")
            except Exception as e:
                log_message(f"Erreur suppression disque {path}: {e}", "WARNING")

        # ISO cloud/clone-init
        iso_kind = 'cloud_init' if 'cloud_init' in vm else ('clone_init' if 'clone_init' in vm else None)
        if iso_kind:
            iso_path = os.path.join(CLOUD_INIT_ISO_DIR, f"{name}-{iso_kind}.iso")
            try:
                if os.path.exists(iso_path):
                    os.remove(iso_path)
                    log_message(f"ISO {iso_path} supprimée", "SUCCESS")
            except Exception as e:
                log_message(f"Impossible de supprimer ISO {iso_path}: {e}", "WARNING")

    def _clean_network(self, network: Dict):
        log_message(f"Suppression du réseau {network['name']}...", "INFO")
        if not any(net.name() == network['name'] for net in self.conn.listAllNetworks()):
            log_message(f"Réseau {network['name']} non trouvé", "WARNING"); return
        net = self.conn.networkLookupByName(network['name'])
        if net.isActive():
            net.destroy()
            log_message(f"Réseau {network['name']} désactivé", "SUCCESS")
        net.undefine()
        log_message(f"Réseau {network['name']} supprimé", "SUCCESS")

    def deploy(self):
        log_message(f"Déploiement de l'infrastructure {self.infra['name']}...", "INFO")
        self.deploy_networks()
        self.deploy_vms()
        self.deploy_firewall()
        log_message("Déploiement terminé !", "SUCCESS")

# Fonctions utilitaires
def netmask(cidr: str) -> str:
    import ipaddress
    network = ipaddress.IPv4Network(cidr, strict=False)
    return str(network.netmask)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Déployer/nettoyer une infrastructure KVM/QEMU.")
    parser.add_argument("yaml_file", help="Chemin vers le fichier YAML")
    parser.add_argument("--clean", action="store_true", help="Nettoyer l'infrastructure")
    args = parser.parse_args()
    try:
        deployer = InfraDeployer(args.yaml_file)
        deployer.check_prerequisites()
        deployer.load_infra()
        if args.clean:
            deployer.clean()
        else:
            deployer.deploy()
    except Exception as e:
        log_message(f"Erreur: {e}", "ERROR")
        exit(1)

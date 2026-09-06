import {
  Laptop,
  Smartphone,
  Tablet,
  Tv,
  Gamepad2,
  Server,
  Cpu,
  Router,
  Printer,
  HardDrive,
  type LucideIcon,
} from 'lucide-react'

export interface DeviceCategoryInfo {
  icon: LucideIcon
  category: string
  label: string
}

export function getDeviceCategory(hostname?: string, vendor?: string): DeviceCategoryInfo {
  const h = (hostname || '').toLowerCase()
  const v = (vendor || '').toLowerCase()

  // Gaming consoles
  if (
    v.includes('sony') ||
    v.includes('nintendo') ||
    h.includes('playstation') ||
    h.includes('ps4') ||
    h.includes('ps5') ||
    h.includes('switch') ||
    h.includes('xbox')
  ) {
    return { icon: Gamepad2, category: 'gaming', label: 'Gaming Console' }
  }

  // Smart TVs & Streaming sticks
  if (
    h.includes('tv') ||
    h.includes('roku') ||
    h.includes('chromecast') ||
    h.includes('firestick') ||
    h.includes('bravia') ||
    v.includes('roku') ||
    v.includes('lg electronics') ||
    v.includes('tcl') ||
    v.includes('hisense')
  ) {
    return { icon: Tv, category: 'tv', label: 'Smart TV / Media' }
  }

  // Printers
  if (
    h.includes('printer') ||
    h.includes('epson') ||
    h.includes('canon') ||
    h.includes('brother') ||
    h.includes('laserjet') ||
    v.includes('canon') ||
    v.includes('epson') ||
    v.includes('brother') ||
    v.includes('hewlett packard') ||
    v.includes('hp inc')
  ) {
    return { icon: Printer, category: 'printer', label: 'Printer' }
  }

  // Servers / NAS / Storage
  if (
    h.includes('nas') ||
    h.includes('server') ||
    h.includes('synology') ||
    h.includes('qnap') ||
    h.includes('truenas') ||
    h.includes('unraid') ||
    v.includes('synology') ||
    v.includes('qnap')
  ) {
    return { icon: Server, category: 'server', label: 'Server / NAS' }
  }

  // IoT / Microcontrollers / Smart Home
  if (
    v.includes('espressif') ||
    v.includes('raspberry') ||
    v.includes('arduino') ||
    v.includes('tuya') ||
    v.includes('sonoff') ||
    v.includes('shelly') ||
    v.includes('esphome') ||
    h.includes('esp_') ||
    h.includes('esphome') ||
    h.includes('tasmota') ||
    h.includes('wled') ||
    h.includes('homeassistant') ||
    h.includes('hue') ||
    v.includes('philips lighting') ||
    v.includes('signify')
  ) {
    return { icon: Cpu, category: 'iot', label: 'IoT / Smart Home' }
  }

  // Network Gear / Routers / Switches / APs
  if (
    v.includes('ubiquiti') ||
    v.includes('cisco') ||
    v.includes('mikrotik') ||
    v.includes('tp-link') ||
    v.includes('netgear') ||
    v.includes('zyxel') ||
    h.includes('ap') ||
    h.includes('switch') ||
    h.includes('router') ||
    h.includes('gateway')
  ) {
    return { icon: Router, category: 'network', label: 'Network Device' }
  }

  // Mobile / Tablets
  if (
    h.includes('iphone') ||
    h.includes('pixel') ||
    h.includes('galaxy') ||
    h.includes('android') ||
    h.includes('oneplus') ||
    h.includes('xiaomi') ||
    h.includes('redmi')
  ) {
    return { icon: Smartphone, category: 'phone', label: 'Smartphone' }
  }

  if (h.includes('ipad') || h.includes('tablet')) {
    return { icon: Tablet, category: 'tablet', label: 'Tablet' }
  }

  // Laptops / PCs
  if (
    h.includes('macbook') ||
    h.includes('laptop') ||
    h.includes('desktop') ||
    h.includes('thinkpad') ||
    h.includes('surface') ||
    v.includes('intel') ||
    v.includes('dell') ||
    v.includes('lenovo') ||
    v.includes('asustek') ||
    v.includes('acer') ||
    v.includes('micro-star')
  ) {
    return { icon: Laptop, category: 'laptop', label: 'Computer / Laptop' }
  }

  // Apple generic
  if (v.includes('apple')) {
    return { icon: Smartphone, category: 'phone', label: 'Apple Device' }
  }

  // Default fallback
  return { icon: HardDrive, category: 'unknown', label: 'Network Client' }
}

/**
 * Checks if a MAC address is locally administered (randomized private address),
 * which is commonly used by iOS (Private Wi-Fi Address), Android (MAC randomization),
 * and Windows for privacy. In IEEE 802, bit 1 of the first octet indicates LAA.
 */
export function isLocallyAdministeredMac(mac?: string): boolean {
  if (!mac) return false
  const clean = mac.trim().replace(/[:-]/g, '')
  if (clean.length < 2) return false
  const firstByte = parseInt(clean.substring(0, 2), 16)
  if (isNaN(firstByte)) return false
  return (firstByte & 0x02) !== 0
}


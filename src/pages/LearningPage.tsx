import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';
import DashboardLayout from '@/components/dashboard/DashboardLayout';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { 
  BookOpen, Lock, Shield, Activity, Code, CheckCircle, ChevronRight, Award, 
  Play, Terminal, Eye, Lightbulb, Brain, Network, Bug, FileSearch, Server,
  AlertTriangle, Zap, Target, Cpu, Database, Globe, Key, Fingerprint,
  RefreshCw, Copy, Check
} from 'lucide-react';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';

interface LiveLab {
  id: string;
  title: string;
  description: string;
  difficulty: 'beginner' | 'intermediate' | 'advanced';
  challenge: string;
  hint: string;
  solution: string;
  validator: (input: string) => boolean;
  completed: boolean;
}

interface Lesson {
  id: string;
  title: string;
  content: string;
  codeExample?: string;
  keyPoints?: string[];
  liveLab?: LiveLab;
  completed: boolean;
}

interface Module {
  id: string;
  title: string;
  description: string;
  icon: typeof Lock;
  color: string;
  lessons: Lesson[];
  completed: boolean;
}

const LearningPage = () => {
  const { user, loading } = useAuth();
  const navigate = useNavigate();
  const [selectedModule, setSelectedModule] = useState<string | null>(null);
  const [selectedLesson, setSelectedLesson] = useState<string | null>(null);
  const [labInput, setLabInput] = useState('');
  const [labResult, setLabResult] = useState<'idle' | 'success' | 'error'>('idle');
  const [showHint, setShowHint] = useState(false);
  const [showSolution, setShowSolution] = useState(false);
  const [copiedCode, setCopiedCode] = useState(false);
  const [codeOutput, setCodeOutput] = useState<string>('');
  const [isRunningCode, setIsRunningCode] = useState(false);

  const [modules, setModules] = useState<Module[]>([
    {
      id: 'crypto',
      title: 'Cryptography Fundamentals',
      description: 'Encryption algorithms used in ransomware and defense',
      icon: Lock,
      color: 'text-primary',
      completed: false,
      lessons: [
        {
          id: 'crypto-1',
          title: 'Symmetric Encryption (AES)',
          completed: false,
          keyPoints: [
            'Same key for encryption and decryption',
            '128-bit blocks with 128/192/256-bit keys',
            'Extremely fast and efficient',
            'Primary encryption method in ransomware'
          ],
          content: `AES (Advanced Encryption Standard) is the most widely used symmetric encryption algorithm. Ransomware uses AES because it's fast enough to encrypt thousands of files quickly.

HOW RANSOMWARE USES AES:
1. Generate a random 256-bit AES key
2. Encrypt all target files with this key
3. Encrypt the AES key with RSA public key
4. Delete the original AES key from memory
5. Demand ransom for the RSA private key`,
          codeExample: `// AES Encryption Example (Web Crypto API)
async function encryptAES(plaintext, key) {
  const encoder = new TextEncoder();
  const data = encoder.encode(plaintext);
  
  const cryptoKey = await crypto.subtle.importKey(
    'raw', key, { name: 'AES-GCM' }, false, ['encrypt']
  );
  
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, cryptoKey, data
  );
  
  return { ciphertext: encrypted, iv };
}`,
          liveLab: {
            id: 'lab-aes',
            title: 'AES Key Generation',
            description: 'Generate a valid 256-bit AES key in hexadecimal',
            difficulty: 'beginner',
            challenge: 'Generate a 64-character hexadecimal string (256 bits) that could be used as an AES key',
            hint: 'A hex string uses characters 0-9 and a-f. 256 bits = 32 bytes = 64 hex characters',
            solution: 'Any 64-character hex string like: a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd',
            validator: (input: string) => /^[0-9a-f]{64}$/i.test(input),
            completed: false
          }
        },
        {
          id: 'crypto-2',
          title: 'Asymmetric Encryption (RSA)',
          completed: false,
          keyPoints: [
            'Public key encrypts, private key decrypts',
            'Much slower than AES',
            'Used for key exchange',
            'Attackers keep private key on their server'
          ],
          content: `RSA uses mathematical properties of large prime numbers. It's computationally infeasible to derive the private key from the public key.

RANSOMWARE HYBRID APPROACH:
1. Attacker generates RSA key pair (2048/4096 bit)
2. Public key embedded in ransomware binary
3. Each victim gets unique AES key
4. AES key encrypted with RSA public key
5. Only attacker's private key can recover AES key`,
          codeExample: `// RSA Key Pair Generation
async function generateRSAKeyPair() {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256'
    },
    true, // extractable
    ['encrypt', 'decrypt']
  );
  return keyPair;
}

// Encrypt with public key
async function encryptRSA(publicKey, data) {
  const encrypted = await crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    publicKey,
    new TextEncoder().encode(data)
  );
  return encrypted;
}`,
          liveLab: {
            id: 'lab-rsa',
            title: 'RSA Key Size',
            description: 'Calculate the security level',
            difficulty: 'beginner',
            challenge: 'What is the minimum recommended RSA key size in bits for secure communication? (Enter the number)',
            hint: 'NIST recommends this as minimum. 1024 is deprecated.',
            solution: '2048',
            validator: (input: string) => input.trim() === '2048',
            completed: false
          }
        },
        {
          id: 'crypto-3',
          title: 'Hashing & File Integrity',
          completed: false,
          keyPoints: [
            'One-way transformation',
            'Fixed output size regardless of input',
            'Used for file integrity verification',
            'Common: SHA-256, MD5 (deprecated)'
          ],
          content: `Hash functions create a unique "fingerprint" of data. Any change to the input produces a completely different hash.

SECURITY APPLICATIONS:
• Password storage (with salt)
• File integrity verification
• Digital signatures
• Malware signature detection
• Blockchain proof-of-work`,
          codeExample: `// SHA-256 Hash Example
async function sha256Hash(message) {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  
  return hashHex;
}

// Usage
const hash = await sha256Hash("Hello World");
console.log(hash);
// Output: a591a6d40bf420404a011733cfb7b190...`,
          liveLab: {
            id: 'lab-hash',
            title: 'Hash Identification',
            description: 'Identify the hash algorithm',
            difficulty: 'beginner',
            challenge: 'This hash is 32 characters long: e10adc3949ba59abbe56e057f20f883e. What algorithm was likely used?',
            hint: 'Count the characters. MD5 produces 128-bit (32 hex char) hashes. SHA-256 produces 64 hex chars.',
            solution: 'MD5',
            validator: (input: string) => input.trim().toUpperCase() === 'MD5',
            completed: false
          }
        }
      ]
    },
    {
      id: 'malware',
      title: 'Malware Analysis',
      description: 'Understanding ransomware behavior and techniques',
      icon: Bug,
      color: 'text-destructive',
      completed: false,
      lessons: [
        {
          id: 'malware-1',
          title: 'Ransomware Families',
          completed: false,
          keyPoints: [
            'WannaCry - EternalBlue exploit (2017)',
            'Ryuk - Targeted enterprise attacks',
            'LockBit - RaaS model',
            'Conti - Double extortion'
          ],
          content: `MAJOR RANSOMWARE FAMILIES:

WANNACRY (2017)
• Exploited SMBv1 vulnerability (EternalBlue)
• Spread across 150+ countries
• $300 Bitcoin ransom per victim
• Kill switch discovered by accident

RYUK (2018-present)
• Targeted attacks on large enterprises
• Manual deployment after network compromise
• Ransoms often exceed $1 million
• Connected to TrickBot/Emotet

LOCKBIT (2019-present)
• Ransomware-as-a-Service model
• Automatic data exfiltration
• Fastest encryption speed claims
• Active affiliate program`,
          liveLab: {
            id: 'lab-ransomware',
            title: 'Ransomware Identification',
            description: 'Identify ransomware by its behavior',
            difficulty: 'intermediate',
            challenge: 'A ransomware sample uses EternalBlue exploit and spreads via SMB. Which famous ransomware family does this describe?',
            hint: 'This 2017 attack affected hospitals, businesses, and government systems worldwide.',
            solution: 'WannaCry',
            validator: (input: string) => input.trim().toLowerCase().includes('wannacry') || input.trim().toLowerCase().includes('wanna cry'),
            completed: false
          }
        },
        {
          id: 'malware-2',
          title: 'Static Analysis Techniques',
          completed: false,
          keyPoints: [
            'Examine without execution',
            'String analysis for IOCs',
            'Import table analysis',
            'PE header inspection'
          ],
          content: `Static analysis examines malware without running it - safer but limited.

TECHNIQUES:
1. STRING EXTRACTION
   - IP addresses, URLs, file paths
   - Ransom note templates
   - Registry keys, mutexes

2. PE HEADER ANALYSIS
   - Compilation timestamp
   - Imported DLLs and functions
   - Sections (.text, .data, .rsrc)

3. ENTROPY ANALYSIS
   - High entropy = encrypted/packed
   - Normal code: ~5-6 bits/byte
   - Packed: >7 bits/byte`,
          codeExample: `# Python: Extract strings from binary
import re

def extract_strings(filepath, min_length=4):
    with open(filepath, 'rb') as f:
        content = f.read()
    
    # ASCII strings
    ascii_strings = re.findall(
        b'[\\x20-\\x7e]{' + str(min_length).encode() + b',}',
        content
    )
    
    # Look for suspicious patterns
    iocs = {
        'urls': re.findall(b'https?://[\\x20-\\x7e]+', content),
        'ips': re.findall(b'\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}', content),
        'emails': re.findall(b'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+', content)
    }
    
    return iocs`,
          liveLab: {
            id: 'lab-static',
            title: 'Entropy Analysis',
            description: 'Identify packed malware',
            difficulty: 'intermediate',
            challenge: 'A PE file section has entropy of 7.8 bits/byte. Is this section likely: "normal", "packed", or "empty"?',
            hint: 'Normal code has entropy around 5-6. Encrypted/packed data approaches 8 (maximum).',
            solution: 'packed',
            validator: (input: string) => input.trim().toLowerCase() === 'packed',
            completed: false
          }
        },
        {
          id: 'malware-3',
          title: 'Dynamic Analysis',
          completed: false,
          keyPoints: [
            'Execute in isolated sandbox',
            'Monitor API calls and behavior',
            'Network traffic capture',
            'File system changes'
          ],
          content: `Dynamic analysis runs malware in a controlled environment to observe behavior.

SANDBOX TOOLS:
• Cuckoo Sandbox (open source)
• Any.Run (interactive)
• Joe Sandbox
• VMware/VirtualBox

WHAT TO MONITOR:
• Process creation/injection
• File operations (encrypt, delete)
• Registry modifications
• Network connections
• API calls (CreateFile, CryptEncrypt)`,
          codeExample: `# Monitor file operations with watchdog
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class RansomwareDetector(FileSystemEventHandler):
    def __init__(self):
        self.file_changes = 0
        self.suspicious_extensions = ['.encrypted', '.locked', '.cry']
    
    def on_modified(self, event):
        self.file_changes += 1
        if self.file_changes > 100:  # Threshold
            print("ALERT: Mass file modification detected!")
    
    def on_created(self, event):
        for ext in self.suspicious_extensions:
            if event.src_path.endswith(ext):
                print(f"ALERT: Suspicious file: {event.src_path}")

# Start monitoring
observer = Observer()
observer.schedule(RansomwareDetector(), path='.', recursive=True)
observer.start()`
        }
      ]
    },
    {
      id: 'detection',
      title: 'Threat Detection',
      description: 'Behavioral analysis and detection techniques',
      icon: Activity,
      color: 'text-warning',
      completed: false,
      lessons: [
        {
          id: 'detect-1',
          title: 'Behavioral Indicators (IOCs)',
          completed: false,
          keyPoints: [
            'Rapid file modifications',
            'Unusual file extensions',
            'Shadow copy deletion',
            'Process injection'
          ],
          content: `INDICATORS OF COMPROMISE (IOCs):

FILE-BASED:
• Mass file renaming/modification
• New suspicious extensions
• Ransom notes appearing
• Encrypted file headers

PROCESS-BASED:
• vssadmin.exe deleting shadows
• bcdedit.exe disabling recovery
• wmic.exe shadow copy deletion
• Unusual parent-child processes

NETWORK-BASED:
• C2 server communication
• Tor traffic
• Data exfiltration patterns`,
          codeExample: `// Detect suspicious file operations
const THRESHOLDS = {
  fileChangesPerSecond: 20,
  encryptedExtensions: ['.encrypted', '.locked', '.cry', '.WNCRY'],
  suspiciousProcesses: ['vssadmin.exe', 'wmic.exe', 'bcdedit.exe']
};

function detectRansomware(fileEvent) {
  // Check file extension
  const ext = fileEvent.path.split('.').pop();
  if (THRESHOLDS.encryptedExtensions.includes('.' + ext)) {
    return { threat: true, reason: 'Suspicious extension detected' };
  }
  
  // Check file change rate
  if (fileChangesPerSecond > THRESHOLDS.fileChangesPerSecond) {
    return { threat: true, reason: 'Abnormal file modification rate' };
  }
  
  return { threat: false };
}`,
          liveLab: {
            id: 'lab-ioc',
            title: 'Identify the Attack',
            description: 'Recognize ransomware behavior',
            difficulty: 'intermediate',
            challenge: 'You see these commands being executed: "vssadmin delete shadows /all /quiet" and "bcdedit /set {default} recoveryenabled No". What is the attacker trying to do?',
            hint: 'VSS = Volume Shadow Copy Service. These are backup/recovery mechanisms.',
            solution: 'Deleting backups',
            validator: (input: string) => {
              const lower = input.toLowerCase();
              return lower.includes('backup') || lower.includes('shadow') || lower.includes('recovery') || lower.includes('restore');
            },
            completed: false
          }
        },
        {
          id: 'detect-2',
          title: 'SIEM & Log Analysis',
          completed: false,
          keyPoints: [
            'Centralized log collection',
            'Real-time correlation',
            'Alert generation',
            'Threat hunting'
          ],
          content: `SIEM (Security Information and Event Management) aggregates logs for threat detection.

KEY LOG SOURCES:
• Windows Event Logs (Security, System)
• Firewall/IDS logs
• Endpoint Detection logs
• Application logs

DETECTION RULES:
• Failed login attempts > threshold
• Process execution anomalies
• Network traffic spikes
• File integrity violations`,
          codeExample: `// Simple SIEM rule example
const siemRules = [
  {
    name: 'Brute Force Detection',
    condition: (events) => {
      const failedLogins = events.filter(e => 
        e.type === 'login_failed' && 
        e.timestamp > Date.now() - 300000 // 5 min
      );
      return failedLogins.length > 5;
    },
    severity: 'HIGH',
    action: 'ALERT'
  },
  {
    name: 'Mass File Encryption',
    condition: (events) => {
      const fileChanges = events.filter(e =>
        e.type === 'file_modified' &&
        e.timestamp > Date.now() - 60000 // 1 min
      );
      return fileChanges.length > 100;
    },
    severity: 'CRITICAL',
    action: 'ISOLATE'
  }
];`
        },
        {
          id: 'detect-3',
          title: 'Machine Learning Detection',
          completed: false,
          keyPoints: [
            'Behavioral anomaly detection',
            'Feature engineering',
            'Model training on normal vs malicious',
            'Real-time classification'
          ],
          content: `ML-based detection learns patterns to identify unknown threats.

FEATURE ENGINEERING:
• File operation frequency
• CPU/Memory patterns
• API call sequences
• Network behavior metrics

ML APPROACHES:
• Random Forest for classification
• Isolation Forest for anomalies
• LSTM for sequence analysis
• Autoencoders for anomaly detection`,
          codeExample: `// Simplified ML detection concept
class RansomwareDetectorML {
  constructor() {
    this.features = [];
    this.threshold = 0.7;
  }
  
  extractFeatures(activity) {
    return {
      fileOpsPerSec: activity.fileOperations / activity.duration,
      cpuUsage: activity.cpuAverage,
      entropyChange: activity.entropyDelta,
      networkConnections: activity.newConnections,
      registryChanges: activity.registryMods
    };
  }
  
  predict(features) {
    // Simplified scoring (real implementation uses trained model)
    const score = (
      (features.fileOpsPerSec > 50 ? 0.3 : 0) +
      (features.cpuUsage > 80 ? 0.2 : 0) +
      (features.entropyChange > 2 ? 0.3 : 0) +
      (features.registryChanges > 10 ? 0.2 : 0)
    );
    
    return score > this.threshold ? 'RANSOMWARE' : 'NORMAL';
  }
}`
        }
      ]
    },
    {
      id: 'response',
      title: 'Incident Response',
      description: 'How to respond to ransomware attacks',
      icon: Shield,
      color: 'text-success',
      completed: false,
      lessons: [
        {
          id: 'response-1',
          title: 'NIST IR Framework',
          completed: false,
          keyPoints: [
            'Preparation',
            'Detection & Analysis',
            'Containment, Eradication, Recovery',
            'Post-Incident Activity'
          ],
          content: `NIST INCIDENT RESPONSE LIFECYCLE:

1. PREPARATION
   • Develop IR plans and playbooks
   • Train response team
   • Maintain offline backups
   • Deploy detection tools

2. DETECTION & ANALYSIS
   • Identify the threat
   • Determine scope and impact
   • Collect and preserve evidence
   • Document timeline

3. CONTAINMENT
   • Isolate infected systems
   • Block lateral movement
   • Preserve forensic evidence

4. ERADICATION
   • Remove malware completely
   • Patch vulnerabilities
   • Reset compromised credentials

5. RECOVERY
   • Restore from clean backups
   • Verify data integrity
   • Resume normal operations

6. POST-INCIDENT
   • Document lessons learned
   • Update procedures
   • Improve defenses`,
          liveLab: {
            id: 'lab-nist',
            title: 'IR Phase Identification',
            description: 'Identify the correct IR phase',
            difficulty: 'beginner',
            challenge: 'The SOC team is disconnecting infected hosts from the network and blocking the attacker\'s C2 IP. Which NIST IR phase is this?',
            hint: 'This phase prevents the threat from spreading further.',
            solution: 'Containment',
            validator: (input: string) => input.trim().toLowerCase().includes('contain'),
            completed: false
          }
        },
        {
          id: 'response-2',
          title: 'Evidence Collection',
          completed: false,
          keyPoints: [
            'Chain of custody',
            'Memory forensics',
            'Disk imaging',
            'Log preservation'
          ],
          content: `DIGITAL FORENSICS ESSENTIALS:

VOLATILE EVIDENCE (Collect First):
• RAM contents
• Running processes
• Network connections
• Logged-in users

NON-VOLATILE EVIDENCE:
• Disk images
• Log files
• Registry hives
• Malware samples

CHAIN OF CUSTODY:
• Document who collected what
• Timestamp all actions
• Calculate file hashes
• Secure storage`,
          codeExample: `# Memory acquisition example (Linux)
# Create memory dump
dd if=/dev/mem of=/evidence/memory.raw bs=1M

# Calculate hash for integrity
sha256sum /evidence/memory.raw > /evidence/memory.hash

# Document collection
echo "Memory acquired by: $USER" >> /evidence/chain_of_custody.txt
echo "Timestamp: $(date -u)" >> /evidence/chain_of_custody.txt
echo "Hash: $(cat /evidence/memory.hash)" >> /evidence/chain_of_custody.txt`
        },
        {
          id: 'response-3',
          title: 'Recovery Strategies',
          completed: false,
          keyPoints: [
            'Backup restoration',
            'Shadow copy recovery',
            'Decryption tools',
            'Never pay ransom'
          ],
          content: `RECOVERY OPTIONS (Priority Order):

1. BACKUP RESTORATION
   ✅ Best option if backups exist
   • Verify backups are not encrypted
   • Test restoration in isolated environment
   • Ensure malware is removed first

2. SHADOW COPIES (Windows)
   ⚠️ Often deleted by ransomware
   • Check immediately upon detection
   • Use vssadmin or shadow explorer
   • May have older versions

3. DECRYPTION TOOLS
   🔍 Check nomoreransom.org
   • Some ransomware has been cracked
   • Law enforcement may have keys
   • No guarantee for new variants

4. PAYING RANSOM (NOT RECOMMENDED)
   ❌ Avoid if possible
   • No guarantee of decryption
   • Funds criminal operations
   • May be targeted again`,
          liveLab: {
            id: 'lab-recovery',
            title: 'Recovery Decision',
            description: 'Choose the best recovery option',
            difficulty: 'intermediate',
            challenge: 'You have clean offline backups from 2 days ago. The ransomware encrypted files today. What is your FIRST priority before restoring?',
            hint: 'If you restore to an infected system, what happens?',
            solution: 'Remove malware',
            validator: (input: string) => {
              const lower = input.toLowerCase();
              return lower.includes('remove') || lower.includes('clean') || lower.includes('eradicate') || lower.includes('malware') || lower.includes('isolate');
            },
            completed: false
          }
        }
      ]
    },
    {
      id: 'network',
      title: 'Network Security',
      description: 'Defending networks against ransomware spread',
      icon: Network,
      color: 'text-cyan-500',
      completed: false,
      lessons: [
        {
          id: 'network-1',
          title: 'Network Segmentation',
          completed: false,
          keyPoints: [
            'Limit lateral movement',
            'Separate critical assets',
            'Zero trust architecture',
            'Micro-segmentation'
          ],
          content: `Network segmentation limits ransomware spread by isolating network zones.

SEGMENTATION STRATEGIES:
• Separate IT and OT networks
• Isolate sensitive data systems
• Create DMZ for public services
• Implement VLANs

ZERO TRUST PRINCIPLES:
• Never trust, always verify
• Least privilege access
• Micro-segmentation
• Continuous authentication`,
          codeExample: `# Firewall rules for segmentation
# Block SMB between segments (prevent WannaCry spread)
iptables -A FORWARD -p tcp --dport 445 -j DROP
iptables -A FORWARD -p tcp --dport 139 -j DROP

# Allow only necessary traffic
iptables -A FORWARD -s 10.1.0.0/24 -d 10.2.0.0/24 -p tcp --dport 443 -j ACCEPT

# Log blocked traffic for analysis
iptables -A FORWARD -j LOG --log-prefix "BLOCKED: "`
        },
        {
          id: 'network-2',
          title: 'Intrusion Detection (IDS/IPS)',
          completed: false,
          keyPoints: [
            'Signature-based detection',
            'Anomaly-based detection',
            'Network vs Host-based',
            'Snort/Suricata rules'
          ],
          content: `IDS/IPS SYSTEMS:

NETWORK-BASED (NIDS):
• Monitor network traffic
• Detect known attack patterns
• Tools: Snort, Suricata, Zeek

HOST-BASED (HIDS):
• Monitor system activity
• File integrity monitoring
• Tools: OSSEC, Wazuh

DETECTION METHODS:
• Signature: Known patterns
• Anomaly: Deviation from baseline
• Behavioral: Suspicious actions`,
          codeExample: `# Snort rule to detect ransomware C2
alert tcp $HOME_NET any -> $EXTERNAL_NET any (
  msg:"Possible Ransomware C2 Communication";
  content:"POST /gate.php";
  content:"Content-Type: application/x-www-form-urlencoded";
  sid:1000001;
  rev:1;
)

# Detect TOR traffic (common for ransomware)
alert tcp any any -> any any (
  msg:"TOR Exit Node Traffic Detected";
  content:"|16 03|";
  content:"|00 00 00|";
  sid:1000002;
  rev:1;
)`
        }
      ]
    },
    {
      id: 'defense',
      title: 'Defense in Depth',
      description: 'Layered security architecture',
      icon: Target,
      color: 'text-purple-500',
      completed: false,
      lessons: [
        {
          id: 'defense-1',
          title: 'Endpoint Protection',
          completed: false,
          keyPoints: [
            'Antivirus/EDR solutions',
            'Application whitelisting',
            'Patch management',
            'Device encryption'
          ],
          content: `ENDPOINT DEFENSE LAYERS:

1. ANTIVIRUS / EDR
   • Signature-based detection
   • Behavioral analysis
   • Threat intelligence feeds
   • Automated response

2. APPLICATION CONTROL
   • Whitelist approved software
   • Block unknown executables
   • Script control (PowerShell, macros)

3. PATCH MANAGEMENT
   • Regular OS updates
   • Application patches
   • Vulnerability scanning

4. DATA PROTECTION
   • Full disk encryption
   • DLP solutions
   • Backup policies`
        },
        {
          id: 'defense-2',
          title: 'Backup Strategies',
          completed: false,
          keyPoints: [
            '3-2-1 backup rule',
            'Air-gapped backups',
            'Regular testing',
            'Immutable storage'
          ],
          content: `3-2-1 BACKUP RULE:

• 3 copies of data
• 2 different media types
• 1 offsite/air-gapped

RANSOMWARE-RESISTANT BACKUPS:
✅ Air-gapped (disconnected)
✅ Immutable storage
✅ Cloud with versioning
✅ Regular restore testing

❌ AVOID:
• Network-attached backups only
• Same credentials as production
• No offline copies`,
          liveLab: {
            id: 'lab-backup',
            title: 'Backup Strategy',
            description: 'Identify backup vulnerabilities',
            difficulty: 'intermediate',
            challenge: 'A company stores backups on a network share accessible from all workstations with domain credentials. Why is this vulnerable to ransomware?',
            hint: 'If ransomware runs with domain user credentials, what can it access?',
            solution: 'Ransomware can encrypt backups',
            validator: (input: string) => {
              const lower = input.toLowerCase();
              return lower.includes('encrypt') || lower.includes('access') || lower.includes('spread') || lower.includes('credential');
            },
            completed: false
          }
        }
      ]
    }
  ]);

  useEffect(() => {
    if (!loading && !user) {
      navigate('/auth');
    }
  }, [user, loading, navigate]);

  const markLessonComplete = (moduleId: string, lessonId: string) => {
    setModules(prev => prev.map(mod => {
      if (mod.id === moduleId) {
        const updatedLessons = mod.lessons.map(les =>
          les.id === lessonId ? { ...les, completed: true } : les
        );
        const allComplete = updatedLessons.every(l => l.completed);
        return { ...mod, lessons: updatedLessons, completed: allComplete };
      }
      return mod;
    }));
    toast.success('Lesson completed!');
  };

  const handleLabSubmit = (moduleId: string, lessonId: string, lab: LiveLab) => {
    if (lab.validator(labInput)) {
      setLabResult('success');
      setModules(prev => prev.map(mod => {
        if (mod.id === moduleId) {
          return {
            ...mod,
            lessons: mod.lessons.map(les => {
              if (les.id === lessonId && les.liveLab) {
                return { ...les, liveLab: { ...les.liveLab, completed: true } };
              }
              return les;
            })
          };
        }
        return mod;
      }));
      toast.success('Correct! Lab completed.');
    } else {
      setLabResult('error');
      toast.error('Incorrect. Try again!');
    }
  };

  const resetLab = () => {
    setLabInput('');
    setLabResult('idle');
    setShowHint(false);
    setShowSolution(false);
  };

  const simulateCodeRun = (code: string) => {
    setIsRunningCode(true);
    setCodeOutput('Running code...\n');
    
    setTimeout(() => {
      const outputs = [
        '> Initializing...',
        '> Loading modules...',
        '> Executing function...',
        `> Result: ${Math.random() > 0.5 ? 'Success!' : 'Completed with output'}`,
        `> Generated hash: ${Math.random().toString(36).substring(2, 15)}`,
        '> Execution time: ' + Math.floor(Math.random() * 100) + 'ms'
      ];
      setCodeOutput(outputs.join('\n'));
      setIsRunningCode(false);
    }, 1500);
  };

  const copyCode = (code: string) => {
    navigator.clipboard.writeText(code);
    setCopiedCode(true);
    toast.success('Code copied!');
    setTimeout(() => setCopiedCode(false), 2000);
  };

  const currentModule = modules.find(m => m.id === selectedModule);
  const currentLesson = currentModule?.lessons.find(l => l.id === selectedLesson);
  const totalLessons = modules.reduce((acc, m) => acc + m.lessons.length, 0);
  const completedLessons = modules.reduce((acc, m) => acc + m.lessons.filter(l => l.completed).length, 0);
  const progressPercent = Math.round((completedLessons / totalLessons) * 100);

  if (loading || !user) return null;

  return (
    <DashboardLayout>
      <div className="mb-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="font-display text-3xl font-bold text-primary text-glow-cyan tracking-wider flex items-center gap-3">
              <BookOpen className="w-8 h-8" />
              LEARNING LAB
            </h1>
            <p className="text-muted-foreground font-mono mt-2">
              Interactive cybersecurity training with live labs
            </p>
          </div>
          <div className="text-right">
            <div className="text-2xl font-bold text-primary">{progressPercent}%</div>
            <div className="text-xs text-muted-foreground font-mono">
              {completedLessons}/{totalLessons} lessons
            </div>
          </div>
        </div>
        
        {/* Progress Bar */}
        <div className="mt-4 h-2 bg-secondary rounded-full overflow-hidden">
          <div 
            className="h-full bg-gradient-to-r from-primary to-success transition-all duration-500"
            style={{ width: `${progressPercent}%` }}
          />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Modules List */}
        <div className="lg:col-span-3 cyber-card p-4 border border-border h-fit">
          <div className="relative z-10">
            <h3 className="font-display font-bold text-foreground mb-4 flex items-center gap-2">
              <Cpu className="w-4 h-4 text-primary" />
              MODULES
            </h3>
            <div className="space-y-2">
              {modules.map(mod => {
                const Icon = mod.icon;
                const completedCount = mod.lessons.filter(l => l.completed).length;
                return (
                  <button
                    key={mod.id}
                    onClick={() => {
                      setSelectedModule(mod.id);
                      setSelectedLesson(mod.lessons[0]?.id || null);
                      resetLab();
                    }}
                    className={cn(
                      "w-full text-left p-3 rounded-lg border transition-all",
                      selectedModule === mod.id
                        ? "bg-primary/10 border-primary"
                        : "bg-secondary/30 border-border/50 hover:border-primary/50"
                    )}
                  >
                    <div className="flex items-center gap-3">
                      <Icon className={cn("w-5 h-5", mod.color)} />
                      <div className="flex-1 min-w-0">
                        <p className="font-mono text-sm font-bold text-foreground truncate">{mod.title}</p>
                        <div className="flex items-center gap-2 mt-1">
                          <div className="flex-1 h-1 bg-secondary rounded-full overflow-hidden">
                            <div 
                              className="h-full bg-success"
                              style={{ width: `${(completedCount / mod.lessons.length) * 100}%` }}
                            />
                          </div>
                          <span className="text-xs text-muted-foreground">
                            {completedCount}/{mod.lessons.length}
                          </span>
                        </div>
                      </div>
                      {mod.completed && <Award className="w-4 h-4 text-success flex-shrink-0" />}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        </div>

        {/* Lessons */}
        {currentModule && (
          <div className="lg:col-span-2 cyber-card p-4 border border-border h-fit">
            <div className="relative z-10">
              <h3 className="font-display font-bold text-foreground mb-4 flex items-center gap-2">
                <FileSearch className="w-4 h-4 text-primary" />
                LESSONS
              </h3>
              <div className="space-y-2">
                {currentModule.lessons.map((lesson, idx) => (
                  <button
                    key={lesson.id}
                    onClick={() => {
                      setSelectedLesson(lesson.id);
                      resetLab();
                    }}
                    className={cn(
                      "w-full text-left p-3 rounded-lg border transition-all flex items-center gap-3",
                      selectedLesson === lesson.id
                        ? "bg-primary/10 border-primary"
                        : "bg-secondary/30 border-border/50 hover:border-primary/50"
                    )}
                  >
                    <span className="text-xs text-muted-foreground font-mono">{idx + 1}</span>
                    {lesson.completed ? (
                      <CheckCircle className="w-4 h-4 text-success flex-shrink-0" />
                    ) : (
                      <ChevronRight className="w-4 h-4 text-muted-foreground flex-shrink-0" />
                    )}
                    <span className="font-mono text-xs text-foreground truncate">{lesson.title}</span>
                    {lesson.liveLab && (
                      <Terminal className={cn(
                        "w-3 h-3 flex-shrink-0",
                        lesson.liveLab.completed ? "text-success" : "text-warning"
                      )} />
                    )}
                  </button>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Lesson Content */}
        <div className={cn(
          "cyber-card p-5 border border-border",
          currentModule ? "lg:col-span-7" : "lg:col-span-9"
        )}>
          <div className="relative z-10">
            {currentLesson ? (
              <div className="space-y-6">
                {/* Header */}
                <div className="flex items-center justify-between">
                  <h2 className="font-display text-xl font-bold text-foreground">{currentLesson.title}</h2>
                  {currentLesson.completed && (
                    <span className="text-xs font-mono text-success flex items-center gap-1 bg-success/10 px-2 py-1 rounded">
                      <CheckCircle className="w-4 h-4" /> Completed
                    </span>
                  )}
                </div>

                {/* Key Points */}
                {currentLesson.keyPoints && (
                  <div className="grid grid-cols-2 gap-2">
                    {currentLesson.keyPoints.map((point, idx) => (
                      <div key={idx} className="flex items-center gap-2 text-sm font-mono text-muted-foreground bg-secondary/30 px-3 py-2 rounded">
                        <Zap className="w-3 h-3 text-warning flex-shrink-0" />
                        {point}
                      </div>
                    ))}
                  </div>
                )}

                {/* Content */}
                <div className="prose prose-invert max-w-none">
                  <pre className="whitespace-pre-wrap text-sm font-mono text-foreground/80 bg-secondary/30 p-4 rounded-lg leading-relaxed">
                    {currentLesson.content}
                  </pre>
                </div>

                {/* Code Example */}
                {currentLesson.codeExample && (
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <h4 className="font-display font-bold text-foreground flex items-center gap-2">
                        <Code className="w-4 h-4 text-accent" />
                        CODE EXAMPLE
                      </h4>
                      <div className="flex gap-2">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => copyCode(currentLesson.codeExample!)}
                        >
                          {copiedCode ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => simulateCodeRun(currentLesson.codeExample!)}
                          disabled={isRunningCode}
                        >
                          <Play className="w-4 h-4 mr-1" />
                          Run
                        </Button>
                      </div>
                    </div>
                    <pre className="text-xs font-mono text-accent bg-background/80 p-4 rounded-lg border border-accent/30 overflow-x-auto">
                      {currentLesson.codeExample}
                    </pre>
                    {codeOutput && (
                      <div className="bg-background p-3 rounded-lg border border-border">
                        <div className="text-xs text-muted-foreground font-mono mb-1">Output:</div>
                        <pre className="text-xs font-mono text-success whitespace-pre-wrap">
                          {codeOutput}
                        </pre>
                      </div>
                    )}
                  </div>
                )}

                {/* Live Lab */}
                {currentLesson.liveLab && (
                  <div className="border-2 border-warning/30 rounded-lg p-5 bg-warning/5">
                    <div className="flex items-center justify-between mb-4">
                      <h4 className="font-display font-bold text-foreground flex items-center gap-2">
                        <Terminal className="w-5 h-5 text-warning" />
                        LIVE LAB: {currentLesson.liveLab.title}
                      </h4>
                      <span className={cn(
                        "text-xs font-mono px-2 py-1 rounded",
                        currentLesson.liveLab.difficulty === 'beginner' && "bg-success/20 text-success",
                        currentLesson.liveLab.difficulty === 'intermediate' && "bg-warning/20 text-warning",
                        currentLesson.liveLab.difficulty === 'advanced' && "bg-destructive/20 text-destructive"
                      )}>
                        {currentLesson.liveLab.difficulty.toUpperCase()}
                      </span>
                    </div>

                    <p className="text-sm text-muted-foreground font-mono mb-4">
                      {currentLesson.liveLab.description}
                    </p>

                    <div className="bg-background/50 p-4 rounded-lg mb-4">
                      <div className="flex items-start gap-2">
                        <Target className="w-5 h-5 text-primary flex-shrink-0 mt-0.5" />
                        <p className="text-sm font-mono text-foreground">
                          {currentLesson.liveLab.challenge}
                        </p>
                      </div>
                    </div>

                    {currentLesson.liveLab.completed ? (
                      <div className="flex items-center gap-2 text-success font-mono text-sm bg-success/10 p-3 rounded-lg">
                        <CheckCircle className="w-5 h-5" />
                        Lab completed successfully!
                      </div>
                    ) : (
                      <>
                        <div className="flex gap-2 mb-4">
                          <Input
                            value={labInput}
                            onChange={(e) => setLabInput(e.target.value)}
                            placeholder="Enter your answer..."
                            className={cn(
                              "font-mono flex-1",
                              labResult === 'success' && "border-success",
                              labResult === 'error' && "border-destructive"
                            )}
                            onKeyDown={(e) => {
                              if (e.key === 'Enter') {
                                handleLabSubmit(currentModule!.id, currentLesson.id, currentLesson.liveLab!);
                              }
                            }}
                          />
                          <Button
                            variant="cyber"
                            onClick={() => handleLabSubmit(currentModule!.id, currentLesson.id, currentLesson.liveLab!)}
                          >
                            Submit
                          </Button>
                        </div>

                        <div className="flex gap-2">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setShowHint(!showHint)}
                          >
                            <Lightbulb className="w-4 h-4 mr-1" />
                            Hint
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setShowSolution(!showSolution)}
                          >
                            <Eye className="w-4 h-4 mr-1" />
                            Solution
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={resetLab}
                          >
                            <RefreshCw className="w-4 h-4 mr-1" />
                            Reset
                          </Button>
                        </div>

                        {showHint && (
                          <div className="mt-3 p-3 bg-primary/10 rounded-lg text-sm font-mono text-primary">
                            💡 {currentLesson.liveLab.hint}
                          </div>
                        )}

                        {showSolution && (
                          <div className="mt-3 p-3 bg-success/10 rounded-lg text-sm font-mono text-success">
                            ✓ {currentLesson.liveLab.solution}
                          </div>
                        )}
                      </>
                    )}
                  </div>
                )}

                {/* Complete Button */}
                {!currentLesson.completed && (
                  <Button
                    variant="success"
                    size="lg"
                    className="w-full"
                    onClick={() => markLessonComplete(currentModule!.id, currentLesson.id)}
                  >
                    <CheckCircle className="w-5 h-5 mr-2" />
                    Mark Lesson as Complete
                  </Button>
                )}
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center h-96 text-center">
                <Brain className="w-20 h-20 text-primary/30 mb-6" />
                <h3 className="font-display text-2xl text-foreground mb-3">Welcome to Learning Lab</h3>
                <p className="text-muted-foreground font-mono text-sm max-w-md mb-6">
                  Master cybersecurity through interactive lessons and hands-on labs.
                  Choose a module from the sidebar to begin your journey.
                </p>
                <div className="grid grid-cols-3 gap-4 text-center">
                  <div className="p-4 bg-secondary/30 rounded-lg">
                    <div className="text-2xl font-bold text-primary">{modules.length}</div>
                    <div className="text-xs text-muted-foreground">Modules</div>
                  </div>
                  <div className="p-4 bg-secondary/30 rounded-lg">
                    <div className="text-2xl font-bold text-warning">{totalLessons}</div>
                    <div className="text-xs text-muted-foreground">Lessons</div>
                  </div>
                  <div className="p-4 bg-secondary/30 rounded-lg">
                    <div className="text-2xl font-bold text-success">
                      {modules.reduce((acc, m) => acc + m.lessons.filter(l => l.liveLab).length, 0)}
                    </div>
                    <div className="text-xs text-muted-foreground">Live Labs</div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default LearningPage;
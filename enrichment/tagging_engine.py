import re
from storage.database import db
from storage.models import FeedItem, Tag, SeverityLevel, IOCType

class ThreatTagger:
    def __init__(self):
        # Threat actor groups (APTs, ransomware gangs, cybercrime groups)
        self.threat_actors = {
            # ========================================
            # APT NUMBERED GROUPS (Mandiant/FireEye naming)
            # ========================================
            'apt1', 'apt 1', 'apt2', 'apt 2', 'apt3', 'apt 3', 'apt4', 'apt 4',
            'apt5', 'apt 5', 'apt6', 'apt 6', 'apt9', 'apt 9', 'apt10', 'apt 10',
            'apt12', 'apt 12', 'apt14', 'apt 14', 'apt15', 'apt 15', 'apt16', 'apt 16',
            'apt17', 'apt 17', 'apt18', 'apt 18', 'apt19', 'apt 19', 'apt20', 'apt 20',
            'apt21', 'apt 21', 'apt22', 'apt 22', 'apt23', 'apt 23', 'apt26', 'apt 26',
            'apt27', 'apt 27', 'apt28', 'apt 28', 'apt29', 'apt 29', 'apt30', 'apt 30',
            'apt31', 'apt 31', 'apt32', 'apt 32', 'apt33', 'apt 33', 'apt34', 'apt 34',
            'apt35', 'apt 35', 'apt36', 'apt 36', 'apt37', 'apt 37', 'apt38', 'apt 38',
            'apt39', 'apt 39', 'apt40', 'apt 40', 'apt41', 'apt 41',
            
            # ========================================
            # APT-C NUMBERED GROUPS (Qihoo 360 naming)
            # ========================================
            'apt-c-00', 'apt-c-06', 'apt-c-09', 'apt-c-12', 'apt-c-17', 'apt-c-23',
            'apt-c-26', 'apt-c-27', 'apt-c-34', 'apt-c-35', 'apt-c-36', 'apt-c-38',
            'apt-c-39', 'apt-c-43',
            
            # ========================================
            # RUSSIAN THREAT ACTORS
            # ========================================
            # APT28 / Fancy Bear cluster
            'fancy bear', 'sofacy', 'pawn storm', 'pawnstorm', 'sednit', 'snakemackerel',
            'tsar team', 'tsarteam', 'strontium', 'swallowtail', 'iron twilight',
            'grizzly steppe', 'apt_sofacy', 'tag_0700', 'group 74', 'sig40', 'tg-4127',
            
            # APT29 / Cozy Bear cluster
            'cozy bear', 'cozy duke', 'cozyduke', 'the dukes', 'dukes', 'euroapt',
            'cozycar', 'cozer', 'office monkeys', 'officemonkeys', 'minidionis',
            'seaduke', 'hammer toss', 'yttrium', 'iron hemlock', 'group 100',
            'unc2452', 'darkhalo', 'stellarparticle', 'nobelium', 'midnight blizzard',
            
            # Turla cluster
            'turla', 'turla group', 'turla team', 'snake', 'venomous bear', 'uroburos',
            'waterbug', 'wraith', 'pfinet', 'krypton', 'pacifier apt', 'popeye',
            'sig23', 'iron hunter', 'makersmark', 'hippo team', 'group 88', 'tag_0530',
            'white bear', 'skipper turla',
            
            # Sandworm cluster
            'sandworm', 'sandworm team', 'black energy', 'blackenergy', 'quedagh',
            'voodoo bear', 'iron viking', 'temp.noble', 'electrum', 'telebots',
            'iridium',
            
            # Energetic Bear / Dragonfly cluster
            'energetic bear', 'dragonfly', 'crouching yeti', 'crouchingyeti', 'havex',
            'koala team', 'iron liberty', 'group 24', 'dymalloy', 'dragonfly 2.0',
            'dragonfly2', 'berserker bear',
            
            # Gamaredon
            'gamaredon', 'gamaredon group', 'primitive bear',
            
            # Other Russian
            'teamspy', 'teamspy crew', 'team bear', 'berserk bear', 'anger bear',
            'iron lyric', 'greyenergy', 'star blizzard', 'cold river', 'nahr elbard',
            'nahr el bared', 'ghostwriter', 'callisto',
            
            # ========================================
            # CHINESE THREAT ACTORS
            # ========================================
            # APT1 / Comment Crew
            'comment crew', 'comment panda', 'pla unit 61398', 'byzantine candor',
            'comment group', 'brown fox', 'gif89a', 'shadyrat', 'shanghai group',
            'tg-8223', 'group 3', 'advanced persistent threat 1',
            
            # APT3 / UPS / Gothic Panda
            'ups', 'ups team', 'gothic panda', 'buckeye', 'boyusec', 'boron',
            'bronze mayfair', 'tg-0110', 'group 6',
            
            # APT10 / Stone Panda
            'stone panda', 'menupass', 'menupass team', 'happyyongzi', 'potassium',
            'duststorm', 'red apollo', 'cvnx', 'hogfish', 'cloud hopper',
            'bronze riverside',
            
            # APT17 / Aurora Panda
            'aurora panda', 'deputy dog', 'hidden lynx', 'tailgater team', 'dogfish',
            'bronze keystone', 'group 8',
            
            # APT27 / Emissary Panda
            'emissary panda', 'tg-3390', 'temp.hippo', 'red phoenix', 'budworm',
            'ziptoken', 'iron tiger', 'bronze union', 'lucky mouse', 'group 35',
            
            # APT40 / Leviathan
            'leviathan', 'temp.periscope', 'temp.jumper', 'bronze mohawk',
            'gadolinium', 'kryptonite panda',
            
            # APT41 / Winnti cluster
            'winnti', 'winnti group', 'winnti umbrella', 'axiom', 'suckfly',
            'blackfly', 'lead', 'wicked spider', 'wicked panda', 'barium',
            'bronze atlas', 'bronze export', 'red kelpie', 'group 72', 'group72',
            
            # Mustang Panda
            'mustang panda', 'bronze president', 'honeymyte', 'red lich',
            
            # Other Chinese APTs
            'anchor panda', 'beijing group', 'sneaky panda', 'elderwood',
            'elderwood gang', 'sig22', 'big panda', 'budminer', 'codoso', 'c0d0so',
            'sunshop group', 'danti', 'dragonok', 'moafee', 'bronze overbrook',
            'dropping elephant', 'chinastrats', 'patchwork', 'monsoon', 'sarit',
            'quilted tiger', 'zinc emerson', 'electric panda', 'eloquent panda',
            'foxy panda', 'gibberish panda', 'hammer panda', 'zhenbao', 'temp.zhenbao',
            'hellsing', 'goblin panda', 'conimes', 'cycldek', 'hurricane panda',
            'black vine', 'temp.avengers', 'ixeshe', 'numbered panda', 'beebus',
            'dyncalc', 'calc team', 'dnscalc', 'crimson iron', 'bronze globe',
            'tg-2754', 'group 22', 'lotus blossom', 'spring dragon', 'st group',
            'esile', 'dragonfish', 'bronze elgin', 'lotus panda', 'elise',
            'lucky cat', 'maverick panda', 'sykipot', 'bronze edison', 'mirage',
            'vixen panda', 'ke3chang', 'gref', 'playful dragon', 'metushy',
            'lurid', 'social network team', 'royal apt', 'bronze palace', 'mofang',
            'superman', 'bronze walker', 'naikon', 'pla unit 78020', 'override panda',
            'camerashy', 'apt.naikon', 'bronze geneva', 'nettraveler', 'travnet',
            'nightshade panda', 'flowerlady', 'flowershow', 'nomad panda',
            'pale panda', 'pirate panda', 'keyboy', 'tropic trooper', 'tropictrooper',
            'bronze hobart', 'pitty panda', 'pittytiger', 'manganese', 'poisonous panda',
            'predator panda', 'putter panda', 'pla unit 61486', 'msupdate', '4hcrew',
            'sulphur', 'searchfire', 'tg-6952', 'sabre panda', 'samurai panda',
            'pla navy', 'wisp team', 'shell crew', 'deep panda', 'webmasters',
            'kungfu kittens', 'pinkpanther', 'sh3llcr3w', 'bronze firestone',
            'group 13', 'siesta', 'spicy panda', 'temper panda', 'admin338',
            'team338', 'admin@338', 'magnesium', 'test panda', 'thrip',
            'tick', 'nian', 'bronze butler', 'redbaldknight', 'stalker panda',
            'tonto team', 'cactuspete', 'karma panda', 'bronze huntley',
            'toxic panda', 'union panda', 'violin panda', 'th3bug', 'twivy',
            'wekby', 'dynamite panda', 'tg-0416', 'scandium', 'wet panda',
            'blacktech', 'circuit panda', 'temp.overboard', 'huapi', 'palmerworm',
            'blackgear', 'topgear', 'comnie', 'hafnium', 'volt typhoon',
            'salt typhoon', 'flax typhoon', 'gallium', 'temp.hermit',
            
            # ========================================
            # NORTH KOREAN THREAT ACTORS
            # ========================================
            # Lazarus cluster
            'lazarus', 'lazarus group', 'hidden cobra', 'dark seoul', 'operation darkseoul',
            'hastati group', 'andariel', 'unit 121', 'bureau 121', 'newromanic cyber army team',
            'bluenoroff', 'group 77', 'labyrinth chollima', 'operation troy',
            'operation ghostsecret', 'operation applejeus', 'stardust chollima',
            'whois hacking team', 'zinc', 'appleworm', 'nickel academy',
            'nickel gladstone', 'covellite',
            
            # Kimsuky
            'kimsuky', 'velvet chollima', 'black banshee', 'thallium',
            'operation stolen pencil',
            
            # Other DPRK
            'silent chollima', 'guardian of peace', 'gop',
            'whois team', 'ricochet chollima', 'reaper', 'reaper group',
            'red eyes', 'operation daybreak', 'operation erebus', 'venus 121',
            'scarcruft', 'group 123', 'group123', 'higaisa', 'honeybee',
            
            # ========================================
            # IRANIAN THREAT ACTORS
            # ========================================
            # APT33 / Elfin
            'elfin', 'magnallium', 'refined kitten', 'holmium', 'cobalt trinity',
            
            # APT34 / OilRig
            'oilrig', 'oil rig', 'twisted kitten', 'cobalt gypsy', 'crambus',
            'helix kitten', 'irn2',
            
            # APT35 / Charming Kitten
            'charming kitten', 'newscaster', 'newscaster team', 'parastoo',
            'ikittens', 'newsbeef', 'group 83',
            
            # APT39 / Chafer
            'chafer', 'remix kitten', 'cobalt hickman',
            
            # Cleaver / Magic Hound cluster
            'cleaver', 'operation cleaver', 'tarh andishan', 'alibaba', '2889',
            'tg-2889', 'rocket_kitten', 'cutting kitten',
            'magic hound', 'temp.beanie', 'ghambar', 'group 41', 'clever kitten',
            'rocket kitten', 'operation woolen goldfish', 'operation woolen-goldfish',
            'thamar reservoir', 'timberworm',
            
            # MuddyWater
            'muddywater', 'muddy water', 'temp.zagros', 'static kitten', 'seedworm',
            'mercury', 'cobalt ulster',
            
            # Other Iranian
            'flying kitten', 'saffronrose', 'saffron rose', 'ajaxsecurityteam',
            'ajax security team', 'sayad', 'group 26', 'fox kitten', 'pioneer kitten',
            'parisite', 'unc757', 'flash kitten', 'infy', 'operation mermaid',
            'prince of persia', 'foudre', 'domestic kitten', 'magic kitten',
            'voyeur', 'group 42', 'tortoiseshell', 'imperial kitten',
            'lyceum', 'cobalt lyceum', 'cadelle', 'tracer kitten',
            'chrysene', 'greenbug', 'darkhydrus', 'lazymeerkat',
            'cobalt dickens', 'mabna institute', 'ta407', 'silent librarian',
            'cobalt edgewater', 'dnspionage', 'cobalt juno', 'saber lion',
            'cobalt katana', 'hive0081', 'sectord01', 'xhunt',
            
            # ========================================
            # OTHER NATION-STATE / REGIONAL ACTORS
            # ========================================
            # Indian
            'sidewinder', 'razor tiger', 'rattlesnake', 't-apt-04',
            'viceroy tiger', 'appin', 'operationhangover', 'dark basin',
            'donot team', 'apt-c-35',
            
            # Pakistani
            'transparent tribe', 'operation c-major', 'c-major', 'mythic leopard',
            'projectm', 'tmp.lapis', 'green havildar', 'copper fieldstone',
            'the gorgon group', 'gorgon group', 'subaat',
            
            # Vietnamese
            'oceanlotus', 'ocean lotus', 'cobalt kitty', 'sealotus', 'sea lotus',
            'ocean buffalo', 'pond loach', 'tin woodlawn', 'bismuth',
            
            # Lebanese
            'volatile cedar', 'reuse team', 'malware reusers', 'dancing salome',
            'lebanese cedar', 'dark caracal',
            
            # Middle Eastern / Other
            'molerats', 'gaza hackers team', 'gaza cybergang', 'operation molerats',
            'extreme jackal', 'moonlight', 'aluminum saratoga', 'aridviper',
            'desert falcon', 'arid viper', 'bahamut', 'goldmouse',
            'golden falcon', 'blind eagle', 'el machete', 'machete', 'machete-apt',
            
            # Turkish
            'promethium', 'strongpity', 'neodymium',
            
            # Israeli
            'unit 8200', 'duqu group', 'stealth falcon', 'fruityarmor',
            
            # Central Asian
            'roaming tiger', 'bronze woodland', 'rotten tomato',
            
            # Southeast Asian
            'rancor', 'rancor group', 'slingshot', 'calypso', 'calypso apt',
            'calypso group', 'gelsemium', 'ta428', 'ta410', 'ta413',
            'platinum', 'twoforone', 'poison carp', 'evil eye',
            'windshift', 'xdspy', 'nazar', 'sig37',
            
            # ========================================
            # EQUATION GROUP / LAMBERTS (NSA-linked)
            # ========================================
            'equation group', 'tilded team', 'lamberts', 'the lamberts', 'eqgrp',
            'longhorn', 'platinum terminal',
            
            # ========================================
            # CYBERCRIME / RANSOMWARE GROUPS
            # ========================================
            # Major Ransomware Operations
            'lockbit', 'lockbit 2.0', 'lockbit 3.0', 'alphv', 'blackcat',
            'royal', 'cl0p', 'clop', 'conti', 'revil', 'sodinokibi',
            'ryuk', 'darkside', 'blackmatter', 'hive', 'vice society',
            'blackbasta', 'black basta', 'akira', 'play', 'rhysida',
            'hunters international', 'cactus', '8base', 'noescape', 'trigona',
            'snatch', 'ragnar locker', 'avoslocker', 'medusa', 'bianlian',
            'karakurt', 'ransomhub', 'dragonforce', 'qilin', 'inc ransom',
            'meow', 'fog', 'embargo', 'lynx', 'sarcoma',
            
            # FIN Groups (Financially Motivated)
            'fin1', 'fin4', 'fin5', 'fin6', 'fin7', 'fin8', 'fin10', 'fin11',
            'skeleton spider', 'itg08', 'magecart group 6', 'white giant',
            'gold franklin', 'carbon spider', 'gold niagara', 'calcium',
            'wolf spider', 'temp.warlock',
            
            # TA Groups
            'ta505', 'ta530', 'ta542', 'ta544', 'ta551', 'ta459', 'ta2101',
            'sectorj04 group', 'graceful spider', 'gold tahoe', 'dudear',
            'shakthak', 'gold cabin', 'maze team', 'twisted spider', 'gold village',
            'gold crestwood', 'narwhal spider', 'gold essex',
            
            # SPIDER Groups (CrowdStrike naming)
            'wizard spider', 'grim spider', 'gold ulrick', 'temp.mixmaster',
            'gold blackburn', 'indrik spider', 'evil corp', 'gold drake',
            'mummy spider', 'doppel spider', 'gold heron', 'pinchy spider',
            'boss spider', 'gold lowell', 'dungeon spider', 'circus spider',
            'clockwork spider', 'cobalt spider', 'gold kingswood', 'cobalt',
            'cobalt group', 'cobalt gang', 'bamboo spider', 'boson spider',
            'guru spider', 'hound spider', 'knockout spider', 'lunar spider',
            'gold swathmore', 'magnetic spider', 'mallard spider', 'gold lagoon',
            'mimic spider', 'monty spider', 'nocturnal spider', 'outlaw spider',
            'overlord spider', 'pizzo spider', 'dd4bc', 'ambiorx', 'ratpak spider',
            'riddle spider', 'salty spider', 'scully spider', 'singing spider',
            'smoky spider', 'solar spider', 'tiny spider', 'traveling spider',
            'union spider', 'venom spider', 'badbullzvenom', 'viking spider',
            'zombie spider', 'anthropoid spider', 'empire monkey', 'cobaltgoblin',
            'andromeda spider',
            
            # GOLD Groups (Secureworks naming)
            'gold burlap', 'gold dupont', 'sprite spider', 'gold evergreen',
            'gold fairfax', 'gold flanders', 'gold galleon', 'gold garden',
            'gold mansard', 'gold northfield', 'gold riverview', 'gold skyline',
            'gold southfield', 'gold symphony', 'gold waterfall', 'gold winter',
            
            # Other Cybercrime
            'carbanak', 'anunak', 'buhtrap', 'gcman', 'moneymaker', 'silence',
            'silence group', 'silence apt group', 'whisper spider', 'rtm',
            'evilnum', 'deathstalker', 'fxmsp', 'gnosticplayers', 'shinyhunters',
            'lapsus', 'lapsus$', 'scattered spider', 'unc3944', 'octo tempest',
            'scatter swine', 'muddled libra', '0ktapus', 'magecart',
            'golden chickens', 'gc01', 'gc02', 'golden chickens01', 'golden chickens02',
            'belialdemon', 'matanbuchus', 'rocke', 'teamtnt', 'pacha group',
            'hookads', 'eviltraffic', 'operation eviltraffic', 'sweed',
            
            # Initial Access Brokers
            'exotic lily', 'prophet spider', 'zebra2104',
            
            # ========================================
            # HACKTIVIST / POLITICAL GROUPS
            # ========================================
            'cyber berkut', 'cyber caliphate army', 'islamic state hacking division',
            'cca', 'united cyber caliphate', 'uuc', 'cybercaliphate',
            'cyber fighters of izz ad-din al qassam', 'fraternal jackal',
            'deadeye jackal', 'syrianelectronicarmy', 'syrian electronic army',
            'corsair jackal', 'tunisiancyberarmy', 'ghost jackal', 'ourmine',
            
            # ========================================
            # OTHER NOTABLE ACTORS
            # ========================================
            'ghostnet', 'snooping dragon', 'shadow network', 'hacking team',
            'dark hotel', 'darkhotel', 'dubnium', 'fallout team', 'karba',
            'luder', 'nemim', 'nemin', 'tapaoux', 'pioneer', 'shadow crane',
            'sig25', 'tungsten bridge', 't-apt-02', 'careto', 'the mask', 'mask',
            'ugly face', 'cloud atlas', 'inception framework', 'red october',
            'the rocra', 'rocra', 'redalpha', 'redecho', 'projectsauron',
            'strider', 'sauron', 'project sauron', 'orangeworm', 'poseidon group',
            'powerpool', 'iamtheking', 'scarlet mimic', 'sea turtle', 'sowbug',
            'the shadow brokers', 'shadow brokers', 'shadowbrokers', 'tsb',
            'whitefly', 'wildneutron', 'butterfly', 'morpho', 'sphinx moth',
            'blue termite', 'cloudy omega', 'emdivi', 'icefog', 'ice fog',
            'dagger panda', 'trident', 'itaduke', 'darkuniverse', 'sig27',
            'blackoasis', 'darkvishnya', 'groundbait', 'group 27', 'group5',
            'henbox', 'invisimole', 'iron group', 'iron cyber group', 'microcin',
            'sixlittlemonkeys', 'nexus zeta', 'night dragon', 'nitro', 'covert grove',
            'oniondog', 'operation bugdrop', 'operation kabar cobra', 'operation parliament',
            'operation poison needles', 'operation shadow force', 'operation shadowhammer',
            'operation sharpshooter', 'operation skeleton key', 'operation soft cell',
            'operation wizardopium', 'operation wocao', 'packrat', 'passcv',
            'roaming mantis', 'roaming mantis group', 'sandcat', 'silverteller',
            'sima', 'snake wine', 'stealth mango', 'tangelo', 'allanite',
            'palmetto fusion', 'attor', 'backdoordiplomacy', 'backdip',
            'cloudcomputating', 'quarian', 'gallmaker', 'golden rat', 'goznym',
            'hummingbad', 'unc1878', 'viceleaker', 'zoopark', 'xenotime',
            'temp.veles', 'terbium', 'taidoor', 'temptick', 'the big bang',
            'raspite', 'leafminer', 'snowglobe', 'animal farm',
            'apt.3102', 'luoxk', 'notrobin', 'vault 7', 'vault 8',
            
            # ========================================
            # 2024-2025 EMERGING ACTORS
            # ========================================
            'scattered lapsus', 'slsh', 'hellcat', 'crimson collective',
            'unc2465', 'unc2628', 'unc6240', 'phosphorus',
        }
        
        # Malware families
        self.malware_families = {
            # Loaders / Droppers
            'qakbot', 'qbot', 'emotet', 'trickbot', 'dridex', 'icedid', 'bumblebee',
            'pikabot', 'darkgate', 'matanbuchus', 'smokeloader', 'amadey', 'ursnif', 'gozi',
            
            # Post-exploitation / C2
            'cobalt strike', 'mimikatz', 'metasploit', 'bloodhound', 'sliver', 'brute ratel',
            'havoc', 'mythic', 'nighthawk', 'covenant', 'merlin',
            
            # Stealers
            'redline', 'vidar', 'raccoon', 'lumma', 'stealc', 'risepro', 'aurora',
            'meta stealer', 'rhadamanthys', 'mystic stealer', 'atomic stealer',
            
            # RATs
            'asyncrat', 'remcos', 'nanocore', 'netwire', 'quasar', 'darkcomet',
            'agent tesla', 'formbook', 'xworm', 'warzone', 'dcrat',
            
            # Ransomware (as malware)
            'lockbit', 'blackcat', 'royal', 'akira', 'play', 'rhysida', 'blackbasta',
            'phobos', 'stop/djvu', 'magniber', 'mallox', 'medusa locker',
            
            # Botnets
            'mirai', 'gafgyt', 'mozi', 'hajime', 'bashlite',
            
            # Wipers / Destructive
            'whispergate', 'hermetic wiper', 'caddy wiper', 'industroyer',
            
            # 2024-2025 malware
            'shinysp1d3r', 'latrodectus', 'voldemort', 'socgholish',
            
            # Generic types
            'ransomware', 'backdoor', 'trojan', 'wiper', 'rootkit',
            'stealer', 'loader', 'rat', 'keylogger', 'spyware', 'botnet', 'infostealer'
        }
        
        # Attack types / Techniques
        self.attack_types = {
            # Delivery methods
            'ransomware', 'phishing', 'spear phishing', 'business email compromise', 'bec',
            'smishing', 'vishing', 'voice phishing', 'callback phishing', 'quishing',
            'malspam', 'malvertising', 'drive-by download', 'watering hole',
            
            # Social engineering
            'social engineering', 'help desk scam', 'it support scam', 'mfa fatigue',
            'sim swapping', 'sim swap', 'account takeover', 'ato',
            
            # Network attacks
            'ddos', 'dos', 'man-in-the-middle', 'mitm', 'arp spoofing', 'dns poisoning',
            
            # Web attacks
            'sql injection', 'sqli', 'xss', 'cross-site scripting', 'csrf', 'ssrf',
            'command injection', 'path traversal', 'lfi', 'rfi', 'xxe', 'deserialization',
            
            # Exploitation
            'rce', 'remote code execution', 'privilege escalation', 'privesc',
            'lateral movement', 'credential theft', 'credential stuffing', 'password spraying',
            'kerberoasting', 'pass-the-hash', 'pass-the-ticket', 'golden ticket',
            
            # Supply chain / Third party
            'supply chain', 'supply chain attack', 'third-party breach', 'dependency confusion',
            'typosquatting', 'software supply chain',
            
            # Data related
            'data breach', 'data leak', 'data exfiltration', 'data theft',
            'double extortion', 'triple extortion', 'extortion',
            
            # Identity attacks
            'inbound federation', 'oauth abuse', 'token theft', 'session hijacking',
            'saml attack', 'golden saml',
            
            # Other
            'zero-day', '0-day', 'exploit', 'vulnerability', 'patch', 'cve',
            'cryptojacking', 'cryptomining', 'insider threat'
        }
        
        # Affected sectors / Industries (expanded from OTX + MITRE)
        self.sectors = {
            # Healthcare
            'healthcare', 'hospital', 'medical', 'pharmaceutical', 'pharma', 'biotech',
            'clinical', 'patient', 'hipaa', 'health system', 'medical device',
            
            # Financial
            'financial', 'banking', 'bank', 'fintech', 'insurance', 'investment',
            'credit union', 'mortgage', 'trading', 'hedge fund', 'private equity',
            'cryptocurrency', 'crypto', 'defi', 'exchange',
            
            # Energy & Utilities
            'energy', 'oil and gas', 'utilities', 'power grid', 'nuclear',
            'electric', 'renewable', 'solar', 'wind', 'pipeline', 'refinery',
            'water', 'wastewater', 'natural gas',
            
            # Government
            'government', 'federal', 'municipal', 'public sector', 'state',
            'city', 'county', 'agency', 'ministry', 'parliament',
            
            # Education
            'education', 'university', 'school', 'academic', 'college',
            'k-12', 'district', 'student', 'campus',
            
            # Retail & E-commerce
            'retail', 'e-commerce', 'ecommerce', 'merchant', 'pos',
            'point of sale', 'shopping', 'consumer',
            
            # Manufacturing & Industrial
            'manufacturing', 'industrial', 'automotive', 'semiconductor',
            'factory', 'plant', 'ics', 'scada', 'plc',
            'operational technology', 'industrial control',
            
            # Transportation & Logistics
            'transportation', 'aviation', 'airline', 'airport', 'shipping',
            'logistics', 'rail', 'railway', 'port', 'maritime', 'trucking',
            
            # Telecom & Communications
            'telecom', 'telecommunications', 'isp', 'carrier', 'mobile',
            'wireless', '5g', 'broadband', 'satellite',
            
            # Critical Infrastructure
            'critical infrastructure', 'cisa', 'national security',
            
            # Defense & Aerospace
            'defense', 'military', 'aerospace', 'contractor',
            'pentagon', 'nato', 'armed forces',
            
            # Legal & Professional Services
            'legal', 'law firm', 'attorney', 'accounting', 'consulting',
            
            # Media & Entertainment
            'media', 'entertainment', 'gaming', 'broadcast', 'streaming',
            'news', 'publishing', 'studio',
            
            # Hospitality & Tourism
            'hospitality', 'hotel', 'casino', 'resort', 'restaurant',
            'travel', 'tourism',
            
            # Technology / IT
            'technology', 'software', 'saas', 'cloud', 'data center',
            'msp', 'managed service', 'it services',
            
            # Real Estate & Construction
            'real estate', 'construction', 'property', 'building',
            
            # Agriculture & Food
            'agriculture', 'farming', 'food', 'beverage', 'food processing',
            
            # Mining & Resources
            'mining', 'resources', 'metals', 'minerals',
            
            # Non-profit & NGO
            'non-profit', 'nonprofit', 'ngo', 'charity', 'foundation'
        }
        
        # Vendors / Technologies / Platforms
        self.vendors = {
            # Microsoft ecosystem
            'microsoft', 'windows', 'exchange', 'active directory', 'sharepoint',
            'office 365', 'o365', 'm365', 'azure', 'entra', 'teams', 'outlook',
            
            # Network / Security vendors
            'cisco', 'fortinet', 'fortigate', 'palo alto', 'juniper', 'checkpoint',
            'sonicwall', 'watchguard', 'barracuda', 'f5', 'ivanti', 'pulse secure',
            'citrix', 'netscaler', 'zscaler', 'crowdstrike', 'sentinelone', 'sophos',
            
            # Infrastructure
            'vmware', 'esxi', 'vcenter', 'proxmox', 'hyper-v', 'nutanix',
            'linux', 'ubuntu', 'redhat', 'red hat', 'centos', 'debian',
            
            # Cloud providers
            'aws', 'amazon web services', 'azure', 'google cloud', 'gcp', 'oracle cloud',
            
            # Cloud platforms / SaaS
            'salesforce', 'salesloft', 'servicenow', 'workday', 'atlassian',
            'jira', 'confluence', 'slack', 'zoom', 'webex',
            
            # Identity / Auth
            'okta', 'duo', 'ping identity', 'auth0', 'onelogin', 'cyberark',
            
            # DevOps / Code
            'gitlab', 'github', 'bitbucket', 'jenkins', 'artifactory',
            'kubernetes', 'k8s', 'docker', 'terraform', 'ansible',
            
            # Databases
            'oracle', 'mysql', 'postgresql', 'mongodb', 'redis', 'elasticsearch',
            
            # Web technologies
            'apache', 'nginx', 'iis', 'tomcat', 'wordpress', 'drupal', 'magento',
            
            # Browsers
            'chrome', 'chromium', 'firefox', 'safari', 'edge',
            
            # Other enterprise
            'sap', 'adobe', 'splunk', 'snowflake', 'databricks',
            'zendesk', 'freshdesk', 'intercom',
            
            # Communication platforms (often abused)
            'telegram', 'discord', 'signal'
        }
        
        # Cybercrime infrastructure / Forums
        self.infrastructure = {
            'breachforums', 'breach forums', 'raidforums', 'raid forums',
            'exploit.in', 'xss.is', 'nulled', 'cracked',
            'genesis market', 'russian market', '2easy',
            'tor', 'onion', 'dark web', 'darknet', 'deep web'
        }
        
        # Security / Hacking Tools (legitimate + abused)
        self.tools = {
            # Network tools
            'nmap', 'masscan', 'shodan', 'censys', 'wireshark', 'tcpdump',
            'netcat', 'socat', 'hping', 'scapy',
            
            # Exploitation frameworks
            'metasploit', 'cobalt strike', 'burp suite', 'sqlmap', 'nikto',
            'nuclei', 'ffuf', 'gobuster', 'dirbuster', 'hydra', 'hashcat',
            'john the ripper', 'aircrack', 'responder', 'impacket',
            
            # Post-exploitation
            'mimikatz', 'bloodhound', 'rubeus', 'kerberoast', 'sharphound',
            'powersploit', 'empire', 'covenant', 'sliver', 'brute ratel',
            'havoc', 'mythic', 'poshc2',
            
            # Credential tools
            'lazagne', 'cain', 'l0phtcrack', 'ophcrack',
            
            # Reverse engineering
            'ida pro', 'ghidra', 'x64dbg', 'ollydbg', 'radare2', 'binary ninja',
            
            # OSINT
            'maltego', 'spiderfoot', 'recon-ng', 'theharvester',
            
            # Cloud tools
            'pacu', 'prowler', 'scoutsuite', 'cloudsploit'
        }
        
        # IoT / Embedded / Hardware
        self.iot = {
            'iot', 'internet of things', 'smart home', 'smart device',
            'embedded', 'firmware', 'router', 'camera', 'dvr', 'nvr',
            'smart tv', 'thermostat', 'smart lock', 'doorbell',
            'wearable', 'medical device', 'pacemaker', 'insulin pump',
            'scada', 'plc', 'hmi', 'rtu', 'ics', 'industrial control',
            'modbus', 'dnp3', 'bacnet', 'opc',
            'zigbee', 'zwave', 'bluetooth', 'lora', 'mqtt',
            'raspberry pi', 'arduino', 'esp32', 'esp8266'
        }
        
        # Major companies (frequent breach targets / vendors)
        self.companies = {
            # Tech giants
            'google', 'apple', 'meta', 'facebook', 'amazon', 'microsoft',
            'twitter', 'x.com', 'linkedin', 'tiktok', 'bytedance', 'netflix',
            'spotify', 'uber', 'lyft', 'airbnb', 'dropbox', 'box',
            
            # Retail
            'walmart', 'target', 'bestbuy', 'best buy', 'home depot', 'lowes',
            'costco', 'kroger', 'walgreens', 'cvs', 'newegg',
            
            # Telecom
            'at&t', 'verizon', 't-mobile', 'sprint', 'comcast', 'spectrum',
            'vodafone', 'telefonica', 'orange', 'bt', 'deutsche telekom',
            
            # Financial
            'jpmorgan', 'bank of america', 'wells fargo', 'citibank', 'goldman sachs',
            'morgan stanley', 'capital one', 'chase', 'american express', 'visa',
            'mastercard', 'paypal', 'stripe', 'square', 'robinhood', 'coinbase',
            
            # Healthcare
            'unitedhealth', 'anthem', 'cigna', 'humana', 'kaiser', 'hca',
            'change healthcare', 'cerner', 'epic systems',
            
            # Auto
            'tesla', 'ford', 'gm', 'toyota', 'volkswagen', 'bmw', 'mercedes',
            'jaguar', 'land rover', 'jaguar land rover',
            
            # Other major corps
            'disney', 'hulu', 'sony', 'nintendo', 'activision',
            'boeing', 'lockheed', 'raytheon', 'northrop',
            'exxon', 'chevron', 'shell', 'bp',
            'fedex', 'ups', 'dhl', 'usps',
            'marriott', 'hilton', 'mgm', 'caesars',
            
            # Tech companies (security relevant)
            'crowdstrike', 'palo alto networks', 'fortinet', 'sentinelone',
            'mandiant', 'fireeye', 'kaspersky', 'symantec', 'norton',
            'mcafee', 'trend micro', 'eset', 'bitdefender', 'avast',
            'splunk', 'elastic', 'datadog', 'sumo logic',
            'okta', 'auth0', 'duo', 'ping identity',
            'cloudflare', 'akamai', 'fastly', 'imperva',
            'snowflake', 'databricks', 'mongodb', 'redis'
        }
        
        # Government agencies / Law enforcement
        self.agencies = {
            'fbi', 'cisa', 'nsa', 'dhs', 'secret service', 'doj',
            'cia', 'dea', 'atf', 'ice', 'cbp', 'tsa',
            'europol', 'interpol', 'ncsc', 'gchq', 'mi5', 'mi6',
            'bka', 'anssi', 'asd', 'cse', 'bsi',
            'nist', 'enisa', 'cert', 'us-cert', 'ic3'
        }
        
        # Severity indicators
        self.severity_keywords = {
            'critical': ['zero-day', 'actively exploited', 'in the wild', 'mass exploitation',
                        'critical vulnerability', 'remote code execution', 'unauthenticated rce',
                        'wormable', 'ransomware', 'data breach'],
            'high': ['high severity', 'privilege escalation', 'authentication bypass',
                    'sql injection', 'credential theft', 'lateral movement',
                    'backdoor', 'supply chain', 'apt'],
            'medium': ['vulnerability', 'security update', 'patch available',
                      'denial of service', 'information disclosure', 'xss'],
            'low': ['security advisory', 'best practices', 'hardening',
                   'configuration', 'awareness']
        }
    
    def extract_tags(self, text):
        """Extract all applicable tags from text"""
        text_lower = text.lower()
        tags = {}
        
        # Threat actors
        for actor in self.threat_actors:
            if actor in text_lower:
                tags[actor] = 'threat_actor'
        
        # Malware families
        for malware in self.malware_families:
            if malware in text_lower:
                tags[malware] = 'malware'
        
        # Attack types
        for attack in self.attack_types:
            if attack in text_lower:
                tags[attack] = 'attack_type'
        
        # Sectors
        for sector in self.sectors:
            if sector in text_lower:
                tags[sector] = 'sector'
        
        # Vendors
        for vendor in self.vendors:
            if vendor in text_lower:
                tags[vendor] = 'vendor'
        
        # Infrastructure
        for infra in self.infrastructure:
            if infra in text_lower:
                tags[infra] = 'infrastructure'
        
        # Tools
        for tool in self.tools:
            if tool in text_lower:
                tags[tool] = 'tool'
        
        # IoT
        for iot in self.iot:
            if iot in text_lower:
                tags[iot] = 'iot'
        
        # Companies
        for company in self.companies:
            if company in text_lower:
                tags[company] = 'company'
        
        # Agencies
        for agency in self.agencies:
            if agency in text_lower:
                tags[agency] = 'agency'
        
        return tags
    
    def calculate_severity(self, text):
        """Calculate severity level based on keywords"""
        text_lower = text.lower()
        
        # Check for critical indicators
        for keyword in self.severity_keywords['critical']:
            if keyword in text_lower:
                return SeverityLevel.CRITICAL
        
        # Check for high severity
        for keyword in self.severity_keywords['high']:
            if keyword in text_lower:
                return SeverityLevel.HIGH
        
        # Check for medium severity
        for keyword in self.severity_keywords['medium']:
            if keyword in text_lower:
                return SeverityLevel.MEDIUM
        
        # Check for low severity
        for keyword in self.severity_keywords['low']:
            if keyword in text_lower:
                return SeverityLevel.LOW
        
        return SeverityLevel.INFO
    
    def calculate_relevance_score(self, feed_item, tags):
        """
        Calculate relevance score 0.0 to 1.0 based on objective metrics.

        Scoring Philosophy:
        - CVE threats: Use CVSS scores (objective, standardized)
        - Non-CVE threats: Use universal threat indicators
        - Environment agnostic: No org-specific tuning

        Score Breakdown:
        - 0.0-0.3: Informational/Low priority
        - 0.3-0.6: Medium priority (monitor)
        - 0.6-0.8: High priority (investigate)
        - 0.8-1.0: Critical priority (immediate action)
        """
        score = 0.0
        text = f"{feed_item.title} {feed_item.content}".lower()

        # ========================================
        # PRIMARY: CVSS-Based Scoring for CVEs
        # ========================================
        max_cvss = 0.0
        has_cve = False

        for ioc in feed_item.iocs:
            if ioc.ioc_type == IOCType.CVE:
                has_cve = True

                # Use CVSS v3 score (preferred), fallback to v2
                cvss_score = ioc.cvss_v3_score or ioc.cvss_v2_score

                if cvss_score:
                    max_cvss = max(max_cvss, cvss_score)

        if max_cvss > 0:
            # Map CVSS 0-10 to relevance 0-0.7
            score += (max_cvss / 10.0) * 0.7

        # ========================================
        # UNIVERSAL THREAT INDICATORS
        # ========================================

        # Threat Actor Activity (+0.2)
        if any(cat == 'threat_actor' for cat in tags.values()):
            score += 0.2

        # Active Exploitation (+0.25)
        if 'actively exploited' in text or 'in the wild' in text or 'exploit available' in text:
            score += 0.25

        # Widespread Malware Campaigns (+0.15)
        if any(cat == 'malware' for cat in tags.values()):
            score += 0.15

        # Zero-Day Vulnerabilities (+0.2)
        if 'zero-day' in text or 'zero day' in text or '0-day' in text:
            score += 0.2

        # Ransomware Activity (+0.2)
        if 'ransomware' in text:
            score += 0.2

        # Data Breach Incidents (+0.15)
        if 'data breach' in text or 'data leak' in text:
            score += 0.15

        # ========================================
        # SOURCE CREDIBILITY BOOSTS
        # ========================================

        # CISA KEV (Known Exploited Vulnerabilities)
        if feed_item.source_name == "CISA KEV":
            score = max(score, 0.95)

        # ========================================
        # PENALTY: Reduce Over-Scoring
        # ========================================

        # If CVE has low CVSS but keywords boost it, cap score
        if has_cve and max_cvss < 7.0:
            score = min(score, 0.6)

        return min(score, 1.0)
    
    def tag_feed_item(self, feed_item_id):
        """Tag and score a single feed item"""
        session = db.get_session()
        
        try:
            feed_item = session.query(FeedItem).filter_by(id=feed_item_id).first()
            if not feed_item:
                return False
            
            text = f"{feed_item.title} {feed_item.content}"
            
            # Extract tags
            tag_dict = self.extract_tags(text)
            
            # Special handling for CISA KEV items
            if feed_item.source_name == "CISA KEV":
                if 'Known Ransomware Use: Known' in text:
                    tag_dict['ransomware-campaign'] = 'attack_type'
            
            # Get or create tags
            for tag_name, category in tag_dict.items():
                tag = session.query(Tag).filter_by(name=tag_name).first()
                if not tag:
                    tag = Tag(name=tag_name, category=category, auto_generated=True)
                    session.add(tag)
                
                if tag not in feed_item.tags:
                    feed_item.tags.append(tag)
            
            # Calculate severity (only if not already set for KEV)
            if feed_item.source_name != "CISA KEV":
                severity = self.calculate_severity(text)
                feed_item.severity = severity

            # Calculate relevance score
            relevance = self.calculate_relevance_score(feed_item, tag_dict)
            
            # Ensure KEV items maintain high relevance
            if feed_item.source_name == "CISA KEV":
                relevance = max(relevance, 0.95)
            
            feed_item.relevance_score = relevance
            
            session.commit()
            return True
            
        except Exception as e:
            print(f"Error tagging feed item {feed_item_id}: {e}")
            session.rollback()
            return False
        finally:
            session.close()
    
    def retag_all(self):
        """Re-tag all feed items (useful after expanding keyword lists)"""
        session = db.get_session()
        
        try:
            all_items = session.query(FeedItem).all()
            items_to_process = [(item.id, item.title[:60]) for item in all_items]
        finally:
            session.close()
        
        tagged_count = 0
        for feed_id, title in items_to_process:
            if self.tag_feed_item(feed_id):
                tagged_count += 1
        
        print(f"Re-tagged {tagged_count} items")
        return tagged_count
    
    def tag_all_untagged(self):
        session = db.get_session()
        
        try:
            # Find items with default relevance score
            untagged = session.query(FeedItem).filter(FeedItem.relevance_score == 0.0).all()
            items_to_process = [(item.id, item.title[:60]) for item in untagged]
        finally:
            session.close()
        
        tagged_count = 0
        for feed_id, title in items_to_process:
            if self.tag_feed_item(feed_id):
                tagged_count += 1
                
                session_check = db.get_session()
                try:
                    updated_item = session_check.query(FeedItem).filter_by(id=feed_id).first()
                    if updated_item:
                        severity = updated_item.severity.value
                        score = updated_item.relevance_score
                        tags = len(updated_item.tags)
                        print(f"Tagged '{title}...' - {severity.upper()} (score: {score:.2f}, tags: {tags})")
                finally:
                    session_check.close()
        
        return tagged_count

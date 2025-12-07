// --- 1. CRYPTO UTILS (Web Crypto API) ---
const CryptoUtils = {
    // Generate RSA Key Pair from a "seed" (Simulated by using seed as entropy for simplicity)
    // NOTE: Real deterministic RSA from seed is hard in WebCrypto. 
    // We will use a simplified approach: Save/Load JWK keys, and use the Seed Phrase to "Encrypt" the Private Key in LocalStorage (Simulation).
    // FOR THIS DEMO: We will just generate a new pair and warn user "This is a demo wallet". 
    // Implementing BIP39 + Deterministic RSA in vanilla JS without huge libraries is complex.
    // OPTION 2: We use the Seed Phrase string to generate an AES Key, and encrypt the RSA Keys with it. 

    generateKeyPair: async () => {
        return await window.crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256"
            },
            true,
            ["encrypt", "decrypt"]
        );
    },

    exportKey: async (key) => {
        const exported = await window.crypto.subtle.exportKey("jwk", key);
        return exported;
    },

    importKey: async (jwk, type) => {
        return await window.crypto.subtle.importKey(
            "jwk",
            jwk,
            {
                name: "RSA-OAEP",
                hash: "SHA-256"
            },
            true,
            type === "public" ? ["encrypt"] : ["decrypt"]
        );
    },

    // Hybrid Encryption: Encrypt Data with AES, Encrypt AES Key with RSA
    encryptForUser: async (dataString, recipientPublicKeyJWK) => {
        // 1. Import Recipient Public Key
        const pubKey = await CryptoUtils.importKey(recipientPublicKeyJWK, "public");

        // 2. Generate random AES Key
        const aesKey = await window.crypto.subtle.generateKey(
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt"]
        );

        // 3. Encrypt Data with AES Key
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encodedData = new TextEncoder().encode(dataString);
        const encryptedContent = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            aesKey,
            encodedData
        );

        // 4. Export AES Key (Raw)
        const rawAesKey = await window.crypto.subtle.exportKey("raw", aesKey);

        // 5. Encrypt AES Key with RSA Public Key
        const encryptedKey = await window.crypto.subtle.encrypt(
            { name: "RSA-OAEP" },
            pubKey,
            rawAesKey
        );

        // Return package
        return {
            iv: Array.from(iv),
            content: Array.from(new Uint8Array(encryptedContent)),
            key: Array.from(new Uint8Array(encryptedKey))
        };
    },

    decryptData: async (encryptedPackage, privateKeyJWK) => {
        try {
            // 1. Import Private Key
            const privKey = await CryptoUtils.importKey(privateKeyJWK, "private");

            // 2. Decrypt AES Key using Private Key
            const encryptedKeyBuffer = new Uint8Array(encryptedPackage.key);
            const rawAesKey = await window.crypto.subtle.decrypt(
                { name: "RSA-OAEP" },
                privKey,
                encryptedKeyBuffer
            );

            // 3. Import AES Key
            const aesKey = await window.crypto.subtle.importKey(
                "raw",
                rawAesKey,
                { name: "AES-GCM" },
                false,
                ["decrypt"]
            );

            // 4. Decrypt Content
            const iv = new Uint8Array(encryptedPackage.iv);
            const contentBuffer = new Uint8Array(encryptedPackage.content);
            const decryptedBuffer = await window.crypto.subtle.decrypt(
                { name: "AES-GCM", iv: iv },
                aesKey,
                contentBuffer
            );

            return new TextDecoder().decode(decryptedBuffer);
        } catch (e) {
            console.error("Decryption failed", e);
            return null; // Likely not for us
        }
    },

    // Simple Hash for Block
    sha256: async (message) => {
        const msgBuffer = new TextEncoder().encode(message);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }
};

// --- 2. IDENTITY SYSTEM (Mnemonic & Key Management) ---
const Identity = {
    // Simplified: We generate a keypair and store it associated with the mnemonic in LocalStorage for demo.
    // In real app, we need BIP39 to derive keys deterministically.

    // Mnemonic Word List (Tiny subset for demo)
    wordList: ["apple", "river", "sky", "mountain", "blue", "code", "crypto", "note", "safe", "music", "light", "star", "ocean", "forest", "fire", "wind"],

    // 4 A. Derive Auth Key from Seed (Used to Encrypt/Decrypt the Wallet on Chain)
    deriveAuthKey: async (mnemonic) => {
        const enc = new TextEncoder();
        const keyMaterial = await window.crypto.subtle.importKey(
            "raw",
            enc.encode(mnemonic),
            { name: "PBKDF2" },
            false,
            ["deriveKey"]
        );
        return await window.crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: enc.encode("BLOCKNOTES_SALT"), // Constant salt for portability
                iterations: 100000,
                hash: "SHA-256"
            },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );
    },

    encryptWalletForChain: async (walletData, mnemonic) => {
        const authKey = await Identity.deriveAuthKey(mnemonic);
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encoded = new TextEncoder().encode(JSON.stringify(walletData));

        const encrypted = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            authKey,
            encoded
        );

        return {
            iv: Array.from(iv),
            data: Array.from(new Uint8Array(encrypted))
        };
    },

    decryptWalletFromChain: async (encryptedPackage, mnemonic) => {
        try {
            const authKey = await Identity.deriveAuthKey(mnemonic);
            const iv = new Uint8Array(encryptedPackage.iv);
            const data = new Uint8Array(encryptedPackage.data);

            const decrypted = await window.crypto.subtle.decrypt(
                { name: "AES-GCM", iv: iv },
                authKey,
                data
            );
            return JSON.parse(new TextDecoder().decode(decrypted));
        } catch (e) {
            return null; // Wrong key
        }
    },

    generateMnemonic: () => {
        const phrase = [];
        for (let i = 0; i < 12; i++) {
            phrase.push(Identity.wordList[Math.floor(Math.random() * Identity.wordList.length)]);
        }
        return phrase.join(" ");
    },

    createWallet: async () => {
        const keyPair = await CryptoUtils.generateKeyPair();
        const publicKey = await CryptoUtils.exportKey(keyPair.publicKey);
        const privateKey = await CryptoUtils.exportKey(keyPair.privateKey);

        const mnemonic = Identity.generateMnemonic();
        const walletData = { publicKey, privateKey, mnemonic };

        // Save locally for immediate use
        localStorage.setItem('wallet_' + mnemonic, JSON.stringify(walletData));

        // Return data AND encrypted package for chain
        const encryptedIdentity = await Identity.encryptWalletForChain(walletData, mnemonic);

        return { walletData, encryptedIdentity };
    },

    login: async (mnemonic, chain) => {
        // 1. Try Local Storage first (Fast path)
        const localData = localStorage.getItem('wallet_' + mnemonic.trim());
        if (localData) {
            const wallet = JSON.parse(localData);
            localStorage.setItem('activeWallet', JSON.stringify(wallet));
            return wallet;
        }

        // 2. Try Recovery from Chain (Slow path)
        if (!chain || chain.length === 0) return null;

        console.log("Scanning chain for identity...");
        for (let i = 1; i < chain.length; i++) {
            const block = chain[i];
            const txn = block.transactions; // Assuming 1 txn/block
            if (txn.type === 'IDENTITY') {
                const recovered = await Identity.decryptWalletFromChain(txn.payload, mnemonic);
                if (recovered) {
                    console.log("Identity Recovered from Chain!");
                    localStorage.setItem('wallet_' + mnemonic, JSON.stringify(recovered));
                    localStorage.setItem('activeWallet', JSON.stringify(recovered));
                    return recovered;
                }
            }
        }

        return null;
    },

    getActiveWallet: () => {
        const data = localStorage.getItem('activeWallet');
        return data ? JSON.parse(data) : null;
    },

    logout: () => {
        localStorage.removeItem('activeWallet');
    }
};

// --- 3. BLOCKCHAIN CORE ---
class Block {
    constructor(timestamp, transactions, previousHash = '') {
        this.timestamp = timestamp;
        this.transactions = transactions;
        // transactions: { id, from: pubKeyJWK, to: pubKeyJWK, secureData: {iv, content, key} }
        this.previousHash = previousHash;
        this.nonce = 0;
        this.hash = '';
    }

    async calculateHash() {
        return await CryptoUtils.sha256(
            this.previousHash +
            this.timestamp +
            JSON.stringify(this.transactions) +
            this.nonce
        );
    }

    async mineBlock(difficulty) {
        this.hash = await this.calculateHash();
        const target = Array(difficulty + 1).join("0");
        while (this.hash.substring(0, difficulty) !== target) {
            this.nonce++;
            this.hash = await this.calculateHash();
        }
    }
}

class Blockchain {
    constructor() {
        this.chain = [];
        this.difficulty = 2;
        this.loadChain();
    }

    loadChain() {
        const saved = localStorage.getItem('localBlockchain');
        if (saved) {
            this.chain = JSON.parse(saved);
            // Re-assign prototype methods if needed (not strictly needed for data objects)
        } else {
            this.initGenesis();
        }
    }

    async initGenesis() {
        const genesisBlock = new Block(Date.now(), "Genesis Block", "0");
        await genesisBlock.mineBlock(this.difficulty);
        this.chain = [genesisBlock];
        this.saveChain();
    }
    getLatestBlock() {
        return this.chain[this.chain.length - 1];
    }

    async addTransaction(transaction) {
        const newBlock = new Block(Date.now(), transaction, this.getLatestBlock().hash);
        console.log("Mining...");
        await newBlock.mineBlock(this.difficulty);

        this.chain.push(newBlock);
        this.saveChain();
        return newBlock;
    }

    saveChain() {
        localStorage.setItem('localBlockchain', JSON.stringify(this.chain));
        window.dispatchEvent(new Event('chainUpdated'));
    }

    // Sync Logic: Replace chain if incoming chain is valid and longer
    replaceChain(newChain) {
        if (newChain.length > this.chain.length) {
            // Validate new chain (Simplified: just length for demo, real: check hashes)
            console.log("Replacing chain with longer connection chain");
            this.chain = newChain;
            this.saveChain();
            return true;
        }
        return false;
    }

    async getDecryptedNotes(wallet) {
        const notes = [];
        // Skip Genesis
        for (let i = 1; i < this.chain.length; i++) {
            const block = this.chain[i];
            const txn = block.transactions; // Assuming 1 txn/block

            // Check if I am "to" or "from" (Match Public Key JWK parameters slightly tricky, we compare stringified JWK)
            // Ideally we compare thumbprints, but string comparison of JWK works if sorted. 
            // We'll trust the "to" field is the exact JWK object.

            const myPub = wallet.publicKey;
            // Check match (simple JSON stringify comparison)
            const isToMe = JSON.stringify(txn.to) === JSON.stringify(myPub);
            const isFromMe = JSON.stringify(txn.from) === JSON.stringify(myPub);

            if (isToMe || isFromMe) {
                let content = "[Encrypted]";
                if (isToMe) {
                    // Try decrypt
                    const decrypted = await CryptoUtils.decryptData(txn.secureData, wallet.privateKey);
                    if (decrypted) content = decrypted;
                } else if (isFromMe) {
                    content = "You sent an encrypted note.";
                    // Technically sender can't decrypt unless they encrypted a copy for themselves too!
                    // In this demo, we only encrypt for Receiver. 
                }

                // Resolving Friend Name for FROM display?
                let displayFrom = isFromMe ? "Me" : "Unknown";
                if (!isFromMe) {
                    // Try to find friend
                    const friend = FriendManager.getFriendByPubKey(txn.from);
                    if (friend) displayFrom = friend.nickname;
                    else displayFrom = "Stranger (" + JSON.stringify(txn.from).substring(0, 10) + "...)";
                }

                notes.push({
                    id: txn.id,
                    timestamp: block.timestamp,
                    from: displayFrom,
                    content: content,
                    isFromMe: isFromMe
                });
            }
        }
        return notes.reverse();
    }
}

// --- 3.5 FRIEND MANAGER ---
const FriendManager = {
    getFriends: () => {
        const saved = localStorage.getItem('blocknotes_friends');
        return saved ? JSON.parse(saved) : {};
    },

    saveFriend: (peerId, nickname, publicKey) => {
        const friends = FriendManager.getFriends();
        // Use PeerID as key for now, or PubKey hash. PeerID changes? 
        // PeerID is transient in PeerJS usually, but we want to map PubKey to Name.
        // Let's key by JSON string of PubKey for stability.
        const key = JSON.stringify(publicKey);
        friends[key] = { nickname, peerId, publicKey };
        localStorage.setItem('blocknotes_friends', JSON.stringify(friends));
        console.log("Friend Saved:", nickname);
        window.dispatchEvent(new Event('friendsUpdated'));
    },

    getFriendByPubKey: (publicKey) => {
        const friends = FriendManager.getFriends();
        return friends[JSON.stringify(publicKey)];
    }
};

// --- 4. NETWORK (PeerJS) ---
class Network {
    constructor(blockchain, onPeerConnected, onDataReceived) {
        this.blockchain = blockchain;
        this.peer = null;
        this.connections = [];
        this.onPeerConnected = onPeerConnected;
        this.onDataReceived = onDataReceived; // Callback to refresh UI
    }

    init() {
        // Create random Peer ID
        this.peer = new Peer(null, {
            debug: 2
        });

        this.peer.on('open', (id) => {
            console.log('My Peer ID is: ' + id);
            document.getElementById('myPeerId').value = id;
            document.getElementById('networkStatus').innerHTML = `<i class="fas fa-wifi"></i> Online (${id.substring(0, 4)})`;
            document.getElementById('networkStatus').classList.add('online');
        });

        this.peer.on('connection', (conn) => {
            this.setupConnection(conn);
        });

        this.peer.on('error', (err) => console.error(err));
    }

    connect(peerId) {
        const conn = this.peer.connect(peerId);
        this.setupConnection(conn);
        return conn;
    }

    setupConnection(conn) {
        conn.on('open', () => {
            console.log("Connected to: " + conn.peer);
            this.connections.push(conn);
            this.onPeerConnected(conn.peer);

            // Handshake: Send my Identity
            const wallet = Identity.getActiveWallet();
            if (wallet) {
                // Generate a random nickname if we don't have one user-set yet.
                // For demo, we use PeerID or generic.
                const myNickname = "User-" + conn.peer.substring(0, 4);
                conn.send({
                    type: 'HANDSHAKE',
                    nickname: myNickname,
                    publicKey: wallet.publicKey
                });
            }

            // Sync: Send my chain
            conn.send({
                type: 'CHAIN_SYNC',
                chain: this.blockchain.chain
            });

            // Discovery: Send my peer list (Gossip)
            this.broadcastPeerList(conn);
        });

        conn.on('data', (data) => {
            console.log("Received data", data);

            if (data.type === 'PEER_DISCOVERY') {
                // Auto-connect to new peers
                this.handlePeerDiscovery(data.peers);
            } else if (data.type === 'HANDSHAKE') {
                // Save Friend!
                FriendManager.saveFriend(conn.peer, data.nickname, data.publicKey);
                alert(`Friend Found! Connected to ${data.nickname}`);

            } else if (data.type === 'CHAIN_SYNC') {
                const replaced = this.blockchain.replaceChain(data.chain);
                if (replaced && this.onDataReceived) this.onDataReceived();
            } else if (data.type === 'NEW_BLOCK') {
                // Add block (Simplified: trust peer)
                this.blockchain.chain.push(data.block);
                this.blockchain.saveChain();
                if (this.onDataReceived) this.onDataReceived();
            }
        });
    }

    broadcastBlock(block) {
        this.connections.forEach(conn => {
            conn.send({
                type: 'NEW_BLOCK',
                block: block
            });
        });
    }

    broadcastHandshake() {
        const wallet = Identity.getActiveWallet();
        if (!wallet) return;

        console.log("Broadcasting Identity to all peers...");
        this.connections.forEach(conn => {
            const myNickname = "User-" + conn.peer.substring(0, 4); // Use peer ID part for nickname consistency or random
            conn.send({
                type: 'HANDSHAKE',
                nickname: myNickname,
                publicKey: wallet.publicKey
            });
        });
    }

    // Gossip Protocol
    broadcastPeerList(targetConn = null) {
        const peers = this.connections.map(c => c.peer);
        const msg = {
            type: 'PEER_DISCOVERY',
            peers: peers
        };

        if (targetConn) {
            targetConn.send(msg);
        } else {
            this.connections.forEach(conn => conn.send(msg));
        }
    }

    handlePeerDiscovery(peerList) {
        peerList.forEach(peerId => {
            // Don't connect to self or existing connections
            if (peerId !== this.peer.id && !this.connections.find(c => c.peer === peerId)) {
                console.log("Discovered new peer via Gossip:", peerId);
                // Connect!
                this.connect(peerId);
            }
        });
    }
}

// --- 5. MAIN APP LOGIC ---
const blockchain = new Blockchain();
const network = new Network(
    blockchain,
    (peerId) => { // On Connect
        const ul = document.getElementById('connectedPeersList');
        const li = document.createElement('li');
        li.innerText = peerId;
        ul.appendChild(li);
        document.getElementById('connectionCount').innerText = `${network.connections.length} Peers`;
    },
    () => { // On Data (Chain updated)
        App.loadNotes();
    }
);

const App = {
    init: () => {
        network.init();
        App.checkSession();
        App.bindEvents();
        window.addEventListener('friendsUpdated', App.updateFriendList);
    },

    checkSession: () => {
        const wallet = Identity.getActiveWallet();
        if (wallet) {
            App.showDashboard(wallet);
            App.updateFriendList();
        } else {
            App.showLogin();
        }
    },

    bindEvents: () => {
        // Tab Switcher
        window.App = App; // Expose for HTML onclick

        // Create Wallet
        document.getElementById('createWalletBtn').addEventListener('click', () => {
            // User confirmed they saved the seed
            const seed = document.getElementById('newSeedDisplay').innerText;
            // We need to trigger the Identity Mine here? No, we do it at creation?
            // Actually, createWallet returned the data, we need to MINE it now if user confirms.
            // Refactor: We mining immediately upon creation in switchLoginTab might be better?
            // Simplification: We assume 'switchLoginTab' (create) generated it. 
            // But we need to mine it. 

            // Let's grab the pendingIdentity from a temp global or re-generate?
            // Better: When "I Have Saved Them" is clicked, we mine the identity block.
            if (window.pendingIdentityPayload) {
                const idTxn = {
                    id: crypto.randomUUID(),
                    type: 'IDENTITY',
                    payload: window.pendingIdentityPayload
                };
                blockchain.addTransaction(idTxn).then(block => {
                    network.broadcastBlock(block);
                    alert("Identity Mined to Chain! You can now recover this wallet on other devices (after sync).");

                    App.switchLoginTab('login');
                    document.getElementById('seedPhraseInput').value = seed;
                });
            }
        });

        // Login
        document.getElementById('loginBtn').addEventListener('click', async () => {
            const btn = document.getElementById('loginBtn');
            const originalText = btn.innerText;
            btn.innerText = "Searching Chain...";
            btn.disabled = true;

            const seed = document.getElementById('seedPhraseInput').value;
            if (!seed) {
                alert("Enter seed phrase");
                btn.innerText = originalText;
                btn.disabled = false;
                return;
            }

            // Sync Warning
            if (blockchain.chain.length <= 1) {
                if (!confirm("Your chain is empty (Genesis only). If this is a new device, you MUST Connect to a Peer first to sync the chain, otherwise recovery will fail. Continue anyway?")) {
                    btn.innerText = originalText;
                    btn.disabled = false;
                    return;
                }
            }

            const wallet = await Identity.login(seed, blockchain.chain);

            if (wallet) {
                App.showDashboard(wallet);
            } else {
                alert("Wallet NOT found in Local Storage OR on the current Chain.\n\n1. Check your Seed Phrase.\n2. Ensure you are Connected to Peers and Synced (Check P2P Manager).\n3. Wait for chain sync if you just connected.");
            }
            btn.innerText = originalText;
            btn.disabled = false;
        });

        // Logout
        document.getElementById('logoutBtn').addEventListener('click', () => {
            Identity.logout();
            location.reload();
        });

        // Copy Public Key
        document.getElementById('copyPublicKeyBtn').addEventListener('click', () => {
            const wallet = Identity.getActiveWallet();
            if (wallet && wallet.publicKey) {
                const keyStr = JSON.stringify(wallet.publicKey);
                navigator.clipboard.writeText(keyStr).then(() => {
                    alert("Public Key Copied to Clipboard! Send this to your friend.");
                });
            }
        });

        // Send Note
        document.getElementById('sendNoteBtn').addEventListener('click', async () => {
            const content = document.getElementById('noteContent').value;
            const recipientStr = document.getElementById('recipientInput').value; // Expecting JWK JSON string?
            // For UX: Recipient Input should be the Peer ID or a Public Key?
            // In typical crypto, it's an address (Hash of PubKey). 
            // For THIS DEMO: We will assume Recipient is "Self" if empty, or try to parse JSON JWK if provided.
            // Simplified: We only support "Note to Self" fully, or we need a way to exchange PubKeys via PeerJS.
            // Let's implement "Exchange Keys" later. For now, user copies their OWN PubKey JWK to send to themselves or others.

            const wallet = Identity.getActiveWallet();
            let recipientKey = wallet.publicKey; // Default to self

            if (recipientStr) {
                try {
                    recipientKey = JSON.parse(recipientStr);
                } catch (e) {
                    alert("Invalid Recipient Key Format (Must be JSON JWK)");
                    return;
                }
            }

            const btn = document.getElementById('sendNoteBtn');
            btn.innerHTML = `<i class="fas fa-cog fa-spin"></i> Mining...`;
            btn.disabled = true;

            // 1. Encrypt
            const secureData = await CryptoUtils.encryptForUser(content, recipientKey);

            // 2. Transact
            const txn = {
                id: crypto.randomUUID(),
                from: wallet.publicKey,
                to: recipientKey,
                secureData: secureData
            };

            const newBlock = await blockchain.addTransaction(txn);
            network.broadcastBlock(newBlock);

            btn.innerHTML = `<i class="fas fa-cube"></i> Encrypt & Mine`;
            btn.disabled = false;
            document.getElementById('noteContent').value = '';
            App.loadNotes();
        });

        // P2P UI
        document.getElementById('toggleP2P').addEventListener('click', () => {
            document.getElementById('p2p-panel').classList.toggle('collapsed');
        });

        document.getElementById('connectPeerBtn').addEventListener('click', () => {
            const id = document.getElementById('peerIdInput').value;
            if (id) network.connect(id);
        });

        document.getElementById('copyPeerBtn').addEventListener('click', () => {
            const id = document.getElementById('myPeerId');
            id.select();
            document.execCommand('copy');
            alert("Copied Peer ID!");
        });
    },

    switchLoginTab: (tab) => {
        if (tab === 'login') {
            document.getElementById('login-tab-content').style.display = 'block';
            document.getElementById('create-tab-content').style.display = 'none';
        } else {
            // Generate new wallet data AND Prepare Identity TXN
            Identity.createWallet().then(res => {
                document.getElementById('newSeedDisplay').innerText = res.walletData.mnemonic;
                window.pendingIdentityPayload = res.encryptedIdentity; // Store for "I Have Saved Them" click
            });
            document.getElementById('login-tab-content').style.display = 'none';
            document.getElementById('create-tab-content').style.display = 'block';
        }
    },

    showLogin: () => {
        document.getElementById('login-view').style.display = 'block';
        document.getElementById('dashboard-view').style.display = 'none';
    },

    showDashboard: (wallet) => {
        document.getElementById('login-view').style.display = 'none';
        document.getElementById('dashboard-view').style.display = 'block';
        // Show truncated key hash or something
        document.getElementById('myAddressDisplay').innerText = "My Wallet Active";

        // Trigger Handshake now that we are logged in
        network.broadcastHandshake();

        App.loadNotes();
    },

    loadNotes: async () => {
        const wallet = Identity.getActiveWallet();
        if (!wallet) return;

        const container = document.getElementById('notesContainer');
        if (!container) return; // Might not exist if markup changed

        container.innerHTML = '<div class="loading">Decrypting Chain...</div>';

        const notes = await blockchain.getDecryptedNotes(wallet);
        container.innerHTML = '';

        if (notes.length === 0) {
            container.innerHTML = '<p class="empty-state">No notes found (or you cannot decrypt them).</p>';
            return;
        }

        notes.forEach(note => {
            const card = document.createElement('div');
            card.className = `note-card ${note.isFromMe ? 'sent' : 'received'}`;
            card.innerHTML = `
                <div class="note-header">
                    <span class="note-type">${note.isFromMe ? 'My Note' : 'Received Note'}</span>
                    <span class="note-time">${new Date(note.timestamp).toLocaleString()}</span>
                </div>
                <div class="note-content">${note.content}</div>
            `;
            container.appendChild(card);
        });

        // Also Add a "My Public Key" copy button somewhere?
        // Let's put it in the console for now or add a button later.
    },

    updateFriendList: () => {
        const friends = FriendManager.getFriends();
        const select = document.getElementById('friendSelector');
        if (!select) return;

        // If no friends, show hint
        if (Object.keys(friends).length === 0) {
            select.innerHTML = '<option value="">No Connected Friends (Sync & Handshake with Peer)</option>';
            return;
        }

        select.innerHTML = '<option value="">Select a Friend...</option>';
        Object.values(friends).forEach(friend => {
            const opt = document.createElement('option');
            // Store stringified key as value
            opt.value = JSON.stringify(friend.publicKey);
            opt.innerText = friend.nickname + " (" + friend.peerId.substring(0, 4) + ")";
            select.appendChild(opt);
        });

        // Auto-fill recipient input on change
        select.onchange = () => {
            document.getElementById('recipientInput').value = select.value;
        };
    }
};

document.addEventListener('DOMContentLoaded', App.init);

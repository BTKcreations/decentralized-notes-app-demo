// --- 1. CORE BLOCKCHAIN LOGIC ---

/**
 * Simulates a cryptographic hash function.
 * In a real app, uses SHA-256. Here we use a simple string hash for readability/speed in simulation,
 * OR we can use Web Crypto API for realism. Let's use a simple reliable hash for this demo's speed.
 */
async function sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

class Block {
    constructor(timestamp, transactions, previousHash = '') {
        this.timestamp = timestamp;
        this.transactions = transactions; // { from, to, content, id }
        this.previousHash = previousHash;
        this.nonce = 0;
        this.hash = ''; // Calculated asynchronously
    }

    async calculateHash() {
        return await sha256(
            this.previousHash +
            this.timestamp +
            JSON.stringify(this.transactions) +
            this.nonce
        );
    }

    async mineBlock(difficulty) {
        this.hash = await this.calculateHash();
        const target = Array(difficulty + 1).join("0"); // e.g., "00"

        while (this.hash.substring(0, difficulty) !== target) {
            this.nonce++;
            this.hash = await this.calculateHash();
        }
        console.log("Block Mined: " + this.hash);
    }
}

class Blockchain {
    constructor() {
        this.chain = [];
        this.difficulty = 2; // Low difficulty for instant feel
        this.pendingTransactions = [];

        // Load chain from local storage if exists
        const savedChain = localStorage.getItem('localBlockchain');
        if (savedChain) {
            this.chain = JSON.parse(savedChain);
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
        // In this simple model, 1 Transaction = 1 Block for simplicity 
        // (Real chains bundle many txns, but for a notes app, immediate save is better).
        const newBlock = new Block(Date.now(), transaction, this.getLatestBlock().hash);

        console.log("Mining new block...");
        await newBlock.mineBlock(this.difficulty);

        this.chain.push(newBlock);
        this.saveChain();
        return newBlock;
    }

    saveChain() {
        localStorage.setItem('localBlockchain', JSON.stringify(this.chain));
        // Dispath event for other tabs
        window.dispatchEvent(new Event('storage'));
    }

    // Get notes relevant to a specific user (Public Key)
    getNotesForUser(publicKey) {
        const notes = [];
        // Skip Genesis block (index 0)
        for (let i = 1; i < this.chain.length; i++) {
            const block = this.chain[i];
            const txn = block.transactions; // Assuming 1 txn per block

            // If I am the sender OR the receiver, I can see this note
            if (txn.to === publicKey || txn.from === publicKey) {
                notes.push({
                    ...txn,
                    timestamp: block.timestamp,
                    blockHash: block.hash
                });
            }
        }
        return notes.reverse(); // Newest first
    }
}

// --- 2. IDENTITY SYSTEM (Simple Simulation) ---

const Identity = {
    generateKeys: async () => {
        // Generating a random "Public Key" (Address)
        // In real web3, this comes from an Elliptic Curve
        const randomBytes = new Uint8Array(16);
        window.crypto.getRandomValues(randomBytes);
        const publicKey = '0x' + Array.from(randomBytes).map(b => b.toString(16).padStart(2, '0')).join('');

        // Private key is just stored locally for login concept (not used for real signing here yet)
        return { publicKey };
    },

    login: (publicKey) => {
        localStorage.setItem('currentUser', publicKey);
        return publicKey;
    },

    getCurrentUser: () => {
        return localStorage.getItem('currentUser');
    },

    logout: () => {
        localStorage.removeItem('currentUser');
    }
};

// --- 3. UI LOGIC ---

const blockchain = new Blockchain();
const App = {
    init: () => {
        App.checkLogin();
        App.bindEvents();
        // Listen for storage changes (multi-tab sync)
        window.addEventListener('storage', () => App.loadNotes());
    },

    checkLogin: () => {
        const user = Identity.getCurrentUser();
        if (user) {
            App.showDashboard(user);
        } else {
            App.showLogin();
        }
    },

    bindEvents: () => {
        // Login Page Events
        document.getElementById('generateBtn')?.addEventListener('click', async () => {
            const keys = await Identity.generateKeys();
            document.getElementById('loginKeyInput').value = keys.publicKey;
        });

        document.getElementById('loginBtn')?.addEventListener('click', () => {
            const key = document.getElementById('loginKeyInput').value;
            if (key) {
                Identity.login(key);
                App.showDashboard(key);
            }
        });

        // Dashboard Events
        document.getElementById('logoutBtn')?.addEventListener('click', () => {
            Identity.logout();
            App.showLogin();
        });

        document.getElementById('sendNoteBtn')?.addEventListener('click', async () => {
            const content = document.getElementById('noteContent').value;
            const recipient = document.getElementById('recipientInput').value;
            const sender = Identity.getCurrentUser();

            if (!content) return alert("Note content cannot be empty");

            // If no recipient specified, send to SELF
            const to = recipient ? recipient : sender;

            const txn = {
                id: crypto.randomUUID(),
                from: sender,
                to: to,
                content: content // In a real app, this would be encrypted with Receiver's Public Key
            };

            const btn = document.getElementById('sendNoteBtn');
            const originalText = btn.innerText;
            btn.innerText = "Mining (Proof of Work)...";
            btn.disabled = true;

            await blockchain.addTransaction(txn);

            btn.innerText = originalText;
            btn.disabled = false;
            document.getElementById('noteContent').value = '';

            App.loadNotes();
        });
    },

    showLogin: () => {
        document.getElementById('login-view').style.display = 'block';
        document.getElementById('dashboard-view').style.display = 'none';
    },

    showDashboard: (publicKey) => {
        document.getElementById('login-view').style.display = 'none';
        document.getElementById('dashboard-view').style.display = 'block';
        document.getElementById('myAddressDisplay').innerText = publicKey;
        App.loadNotes();
    },

    loadNotes: () => {
        const currentUser = Identity.getCurrentUser();
        if (!currentUser) return;

        const notes = blockchain.getNotesForUser(currentUser);
        const container = document.getElementById('notesContainer');
        container.innerHTML = '';

        if (notes.length === 0) {
            container.innerHTML = '<p class="empty-state">No notes found on the chain for you.</p>';
            return;
        }

        notes.forEach(note => {
            const isFromMe = note.from === currentUser;
            const card = document.createElement('div');
            card.className = `note-card ${isFromMe ? 'sent' : 'received'}`;

            card.innerHTML = `
                <div class="note-header">
                    <span class="note-type">${isFromMe ? 'Sent by Me' : 'Received'}</span>
                    <span class="note-time">${new Date(note.timestamp).toLocaleString()}</span>
                </div>
                <div class="note-content">${note.content}</div>
                <div class="note-footer">
                    <span>From: ${note.from.substring(0, 8)}...</span>
                    <span>To: ${note.to.substring(0, 8)}...</span>
                </div>
            `;
            container.appendChild(card);
        });
    }
};

// Wait for DOM
document.addEventListener('DOMContentLoaded', App.init);

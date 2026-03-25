import eth_account
import random
import string
import json
from pathlib import Path
from web3 import Web3
from eth_account.messages import encode_defunct
from web3.middleware import ExtraDataToPOAMiddleware 

def merkle_assignment():
    """
        The only modifications you need to make to this method are to assign
        your "random_leaf_index" and uncomment the last line when you are
        ready to attempt to claim a prime. You will need to complete the
        methods called by this method to generate the proof.
    """
    # Generate the list of primes as integers
    num_of_primes = 8192
    primes = generate_primes(num_of_primes)

    # Create a version of the list of primes in bytes32 format
    leaves = convert_leaves(primes)

    # Build a Merkle tree using the bytes32 leaves as the Merkle tree's leaves
    tree = build_merkle(leaves)

    # Select a random leaf and create a proof for that leaf
    random_leaf_index = 10 #TODO generate a random index from primes to claim (0 is already claimed)
    proof = prove_merkle(tree, random_leaf_index)

    # This is the same way the grader generates a challenge for sign_challenge()
    challenge = ''.join(random.choice(string.ascii_letters) for i in range(32))
    # Sign the challenge to prove to the grader you hold the account
    addr, sig = sign_challenge(challenge)

    if sign_challenge_verify(challenge, addr, sig):
        # tx_hash = '0x'
        # TODO, when you are ready to attempt to claim a prime (and pay gas fees),
        #  complete this method and run your code with the following line un-commented
        tx_hash = send_signed_msg(proof, leaves[random_leaf_index])

def generate_primes(num_primes):
    """Generates the first n primes using a basic sieve or trial division."""
    primes_list = []
    num = 2
    while len(primes_list) < num_primes:
        for i in range(2, int(num**0.5) + 1):
            if (num % i) == 0:
                break
        else:
            primes_list.append(num)
        num += 1
    return primes_list

def convert_leaves(primes_list):
    """Converts integers to 32-byte big-endian format."""
    # Each leaf must be exactly 32 bytes for the Keccak256 hash function
    return [int.to_bytes(p, 32, 'big') for p in primes_list]

def build_merkle(leaves):
    """
    Builds the tree layer by layer. 
    tree[0] = leaves, tree[1] = parents, ..., tree[n] = root
    """
    tree = [leaves]
    current_layer = leaves
    
    while len(current_layer) > 1:
        next_layer = []
        # Process pairs. If odd number of nodes, the last one moves up (standard Merkle)
        # Note: hash_pair handles the sorting required by OpenZeppelin
        for i in range(0, len(current_layer), 2):
            if i + 1 < len(current_layer):
                next_layer.append(hash_pair(current_layer[i], current_layer[i+1]))
            else:
                # If there's an odd node at the end, hash it with itself or carry up
                # Most implementations carry it up or hash with itself.
                next_layer.append(current_layer[i])
        tree.append(next_layer)
        current_layer = next_layer
        
    return tree

def prove_merkle(merkle_tree, random_indx):
  """Generates the sibling hashes needed to reconstruct the root."""
  merkle_proof = []
  index = random_indx
  
  # Iterate through layers (excluding the root layer)
  for layer in merkle_tree[:-1]:
      if index % 2 == 1:
          sibling_idx = index - 1
      else:
          sibling_idx = index + 1
          
      if sibling_idx < len(layer):
          # CHANGE THIS LINE: 
          # Remove .hex() - the grader wants raw bytes
          merkle_proof.append(layer[sibling_idx]) 
          
      index //= 2
      
  return merkle_proof

def sign_challenge(challenge):
    """Signs a text message to prove ownership of the private key."""
    acct = get_account()
    addr = acct.address
    
    # Standard EIP-191 Ethereum signed message
    eth_encoded_msg = encode_defunct(text=challenge)
    eth_sig_obj = acct.sign_message(eth_encoded_msg)

    return addr, eth_sig_obj.signature.hex()

def send_signed_msg(proof, random_leaf):
    """Calls the 'submit' function on the smart contract."""
    chain = 'bsc'
    acct = get_account()
    address, abi = get_contract_info(chain)
    w3 = connect_to(chain)
    
    contract = w3.eth.contract(address=address, abi=abi)
    
    # Build transaction
    # Note: 'submit' is the function name based on assignment description
    tx = contract.functions.submit(proof, random_leaf).build_transaction({
        'from': acct.address,
        'nonce': w3.eth.get_transaction_count(acct.address),
        'gas': 200000, # Estimated gas
        'gasPrice': w3.eth.gas_price
    })
    
    signed_tx = w3.eth.account.sign_transaction(tx, private_key=acct.key)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    
    return tx_hash.hex()

def hash_pair(a, b):
    # This must be present in your environment!
    if a < b:
        return Web3.solidity_keccak(['bytes32', 'bytes32'], [a, b])
    else:
        return Web3.solidity_keccak(['bytes32', 'bytes32'], [b, a])

def connect_to(chain):
    if chain not in ['avax','bsc']:
        return None
    if chain == 'avax':
        api_url = f"https://api.avax-test.network/ext/bc/C/rpc"
    else:
        api_url = f"https://data-seed-prebsc-1-s1.binance.org:8545/"
    w3 = Web3(Web3.HTTPProvider(api_url))
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    return w3

def get_account():
    cur_dir = Path(__file__).parent.absolute()
    with open(cur_dir.joinpath('sk.txt'), 'r') as f:
        sk = f.readline().rstrip()
    if sk[0:2] == "0x":
        sk = sk[2:]
    return eth_account.Account.from_key(sk)

def get_contract_info(chain):
    """
    Returns a contract address and contract abi from "contract_info.json"
    """
    # Try the current directory first
    cur_dir = Path(__file__).parent.absolute()
    contract_file = cur_dir / "contract_info.json"
    
    # If not found, check the parent directory (common in Codio/GitHub clones)
    if not contract_file.is_file():
        contract_file = cur_dir.parent / "contract_info.json"
        
    # If still not found, check the specific path from your error message
    if not contract_file.is_file():
        contract_file = Path('/home/codio/workspace/.guides/student_code/Merkle-Trees/contract_info.json')

    with open(contract_file, "r") as f:
        d = json.load(f)
        d = d[chain]
    return d['address'], d['abi']

def sign_challenge_verify(challenge, addr, sig):
    eth_encoded_msg = eth_account.messages.encode_defunct(text=challenge)
    if eth_account.Account.recover_message(eth_encoded_msg, signature=sig) == addr:
        print(f"Success: signed the challenge {challenge} using address {addr}!")
        return True
    return False

if __name__ == "__main__":
    merkle_assignment()

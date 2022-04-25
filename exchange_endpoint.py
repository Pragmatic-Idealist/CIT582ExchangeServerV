from flask import Flask, request, g
from flask_restful import Resource, Api
from sqlalchemy import create_engine
from flask import jsonify
import json
import eth_account
import algosdk
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import load_only
from datetime import datetime
import math
import sys
import traceback

# TODO: make sure you implement connect_to_algo, send_tokens_algo, and send_tokens_eth
from send_tokens import connect_to_algo, connect_to_eth, send_tokens_algo, send_tokens_eth

from models import Base, Order, TX
engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

app = Flask(__name__)

""" Pre-defined methods (do not need to change) """

@app.before_request
def create_session():
    g.session = scoped_session(DBSession)

@app.teardown_appcontext
def shutdown_session(response_or_exc):
    sys.stdout.flush()
    g.session.commit()
    g.session.remove()

def connect_to_blockchains():
    try:
        # If g.acl has not been defined yet, then trying to query it fails
        acl_flag = False
        g.acl
    except AttributeError as ae:
        acl_flag = True
    
    try:
        if acl_flag or not g.acl.status():
            # Define Algorand client for the application
            g.acl = connect_to_algo()
    except Exception as e:
        print("Trying to connect to algorand client again")
        print(traceback.format_exc())
        g.acl = connect_to_algo()
    
    try:
        icl_flag = False
        g.icl
    except AttributeError as ae:
        icl_flag = True
    
    try:
        if icl_flag or not g.icl.health():
            # Define the index client
            g.icl = connect_to_algo(connection_type='indexer')
    except Exception as e:
        print("Trying to connect to algorand indexer client again")
        print(traceback.format_exc())
        g.icl = connect_to_algo(connection_type='indexer')

        
    try:
        w3_flag = False
        g.w3
    except AttributeError as ae:
        w3_flag = True
    
    try:
        if w3_flag or not g.w3.isConnected():
            g.w3 = connect_to_eth()
    except Exception as e:
        print("Trying to connect to web3 again")
        print(traceback.format_exc())
        g.w3 = connect_to_eth()
        
""" End of pre-defined methods """
        
""" Helper Methods (skeleton code for you to implement) """

def log_message(message_dict):
    new_msg = Log(message=json.dumps(d))
    g.sesion.add(new_log)
    g.session.commit()

    # TODO: Add message to the Log table

def get_algo_keys():
    
    # TODO: Generate or read (using the mnemonic secret) 
    # the algorand public/private keys
    algo_sk, algo_pk = account.generate_account()
    
    return algo_sk, algo_pk


def get_eth_keys(filename = "eth_mnemonic.txt"):
    w3 = Web3()
    
    # TODO: Generate or read (using the mnemonic secret) 
    # the ethereum public/private keys
    with open(filename,'r') as f:
        mnemonic_secret = f.read().strip()

    eth_account.Account.enable_unaudited_hdwallet_features()
    account = eth_account.Account.from_mnemonic(mnemonic_secret)
    
    eth_pk = account.address 
    eth_sk = account.keys
    return eth_sk, eth_pk
  
def fill_order(order, txes=[]):
    # TODO: 
    # Match orders (same as Exchange Server II)
    # Validate the order has a payment to back it (make sure the counterparty also made a payment)
    # Make sure that you end up executing all resulting transactions!
    
    #insert new order into database
    new_order = Order( sender_pk=order.sender_pk,receiver_pk=order.receiver_pk, 
    buy_currency=order.buy_currency, sell_currency=order.sell_currency, 
    buy_amount=order.buy_amount, sell_amount=order.sell_amount )
    
    g.session.add(new_order)
    g.session.commit()

    #check for a match

    #grab data from database
    orders = g.session.query(Order).filter(Order.filled == None).all() #create a interable to look through orders

    for existing_order in orders:
        if ((existing_order.buy_currency == new_order.sell_currency) and (existing_order.sell_currency == new_order.buy_currency) 
        and (existing_order.sell_amount / existing_order.buy_amount >= new_order.buy_amount/new_order.sell_amount) 
        and (new_order.buy_amount/existing_order.buy_amount<=new_order.sell_amount/existing_order.sell_amount)):
            # set filled to current time stamp
            new_order.filled = datetime.now()
            existing_order.filled = datetime.now()
            
            # setting counterparty id to each other
            existing_order.counterparty_id = new_order.id
            new_order.counterparty_id = existing_order.id
            
            update_new_order = g.session.query(Order).filter(Order.id == new_order.id).first() 
            update_existing_order = g.session.query(Order).filter(Order.id == existing_order.id).first()
            
            update_new_order = new_order
            update_existing_order= existing_order

            #commit changes
            g.session.commit()

            # order buy sell relationship
            ratio = new_order.buy_amount/new_order.sell_amount

            if (new_order.sell_amount < existing_order.buy_amount):
                # create child order
                new_order = Order(sender_pk=existing_order.sender_pk,receiver_pk=existing_order.receiver_pk, buy_currency=existing_order.buy_currency, 
                sell_currency=existing_order.sell_currency, buy_amount=existing_order.buy_amount - new_order.sell_amount, 
                sell_amount= ratio* (existing_order.buy_amount - new_order.sell_amount), creator_id = existing_order.id)
                
                #add child order to session
                g.session.add(new_order)
                g.session.commit()
                break
            elif (new_order.buy_amount > existing_order.sell_amount):
                # create child order
                new_order = Order(sender_pk=new_order.sender_pk,receiver_pk=new_order.receiver_pk, buy_currency=new_order.buy_currency, 
                sell_currency=new_order.sell_currency, buy_amount=new_order.buy_amount - existing_order.sell_amount, 
                sell_amount= ratio*(new_order.buy_amount - existing_order.sell_amount), creator_id = new_order.id)

                #add child order to session
                g.session.add(new_order)
                g.session.commit()
                break
            else:
              break
def execute_txes(txes):
    if txes is None:
        return True
    if len(txes) == 0:
        return True
    print( f"Trying to execute {len(txes)} transactions" )
    print( f"IDs = {[tx['order_id'] for tx in txes]}" )
    eth_sk, eth_pk = get_eth_keys()
    algo_sk, algo_pk = get_algo_keys()
    
    if not all( tx['platform'] in ["Algorand","Ethereum"] for tx in txes ):
        print( "Error: execute_txes got an invalid platform!" )
        print( tx['platform'] for tx in txes )

    algo_txes = [tx for tx in txes if tx['platform'] == "Algorand" ]
    eth_txes = [tx for tx in txes if tx['platform'] == "Ethereum" ]

    # TODO: 
    #       1. Send tokens on the Algorand and eth testnets, appropriately
    #          We've provided the send_tokens_algo and send_tokens_eth skeleton methods in send_tokens.py
    #       2. Add all transactions to the TX table

    send_tokens_algo(g.acl, algo_sk, algo_txes) # algorand
    send_tokens_eth(g.w3, eth_sk, eth_txes) # eth

    # add transactions
    g.session.add_all(algo_txes)
    g.session.add_all(eth_txes)
    g.session.commit()

""" End of Helper methods"""
  
@app.route('/address', methods=['POST'])
def address():
    if request.method == "POST":
        content = request.get_json(silent=True)
        if 'platform' not in content.keys():
            print( f"Error: no platform provided" )
            return jsonify( "Error: no platform provided" )
        if not content['platform'] in ["Ethereum", "Algorand"]:
            print( f"Error: {content['platform']} is an invalid platform" )
            return jsonify( f"Error: invalid platform provided: {content['platform']}"  )
        
        if content['platform'] == "Ethereum":
            #Your code here
            return jsonify( eth_pk )
        if content['platform'] == "Algorand":
            #Your code here
            return jsonify( algo_pk )

@app.route('/trade', methods=['POST'])
def trade():
    print( "In trade", file=sys.stderr )
    connect_to_blockchains()
    get_keys()
    if request.method == "POST":
        content = request.get_json(silent=True)
        columns = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform", "tx_id", "receiver_pk"]
        fields = [ "sig", "payload" ]
        error = False
        for field in fields:
            if not field in content.keys():
                print( f"{field} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            return jsonify( False )
        
        error = False
        for column in columns:
            if not column in content['payload'].keys():
                print( f"{column} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            return jsonify( False )
        
        # Your code here
        
        # 1. Check the signature
        
        # 2. Add the order to the table
        
        # 3a. Check if the order is backed by a transaction equal to the sell_amount (this is new)

        # 3b. Fill the order (as in Exchange Server II) if the order is valid
        
        # 4. Execute the transactions
        
        # If all goes well, return jsonify(True). else return jsonify(False)
        sig = content['sig']
        message = json.dumps(content['payload'])
        pk = content['payload']['sender_pk']
        platform = content['payload']['platform']

        #Check whether is ethereum or algorand
        if platform == 'Ethereum':
            eth_encoded_msg = eth_account.messages.encode_defunct(text=message)
            if eth_account.Account.recover_message(eth_encoded_msg,signature=sig) == pk:
                order_obj = Order( sender_pk=content['payload']['sender_pk'], receiver_pk=content['payload']['receiver_pk'], buy_currency=content['payload']['buy_currency'], sell_currency=content['payload']['sell_currency'], 
                buy_amount=content['payload']['buy_amount'], 
                sell_amount=content['payload']['sell_amount'], 
                signature = content['sig'] )

                fill_order(order_obj) # filling order

                g.session.add(order_obj)
                g.session.commit()

                return jsonify(True)
            else:
                log_message(json.dumps(content['payload']))
                g.session.commit()
                return jsonify(False)

        else:
            algo_sig_str = sig
            if algosdk.util.verify_bytes(message.encode('utf-8'),algo_sig_str,pk):
                order_obj = Order( sender_pk=content['payload']['sender_pk'],
                receiver_pk=content['payload']['receiver_pk'], 
                buy_currency=content['payload']['buy_currency'], 
                sell_currency=content['payload']['sell_currency'], 
                buy_amount=content['payload']['buy_amount'], 
                sell_amount=content['payload']['sell_amount'], 
                signature = content['sig'] )

                fill_order(order_obj) # filling order

                g.session.add(order_obj)
                g.session.commit()
                return jsonify(True)
            else:
                log_message(json.dumps(content['payload']))
                g.session.commit()
                return jsonify(False)
    else:
      return jsonify(True)

@app.route('/order_book')
def order_book():
    #grab all data from database
    #data = g.session.query(Order).all() #all orders 
    orders = {'data':[]}
    #result = {'data' :g.session.query(Order).all()}
    
    transactions = g.session.query(Order)

    for transaction in transactions:
      transaction_dict = {}
      transaction_dict['sender_pk'] = transaction.sender_pk
      transaction_dict['receiver_pk'] = transaction.receiver_pk
      transaction_dict['buy_currency'] = transaction.buy_currency
      transaction_dict['sell_currency'] = transaction.sell_currency
      transaction_dict['buy_amount'] = transaction.buy_amount
      transaction_dict['sell_amount'] = transaction.sell_amount
      transaction_dict['signature'] = transaction.signature
      
      orders['data'].append(transaction_dict)
    
    
    return jsonify(orders)

if __name__ == '__main__':
    app.run(port='5002')

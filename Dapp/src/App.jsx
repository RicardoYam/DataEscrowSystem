import React, { useEffect, useState } from 'react';
import './App.css';
import Web3 from 'web3';
import axios from 'axios';
import { v4 as uuidv4 } from 'uuid';
import CryptoJS from 'crypto-js';

function App() {
  const ownerId = 1;
  const requester = "user1";
  const hardcodeJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

  const [web3, setWeb3] = useState(null);
  const [contract, setContract] = useState(null);
  const [accounts, setAccounts] = useState([]);
  const [response, setResponse] = useState('');
  const [responseBlockHash, setResponseBlockHash] = useState('');
  const [error, setError] = useState('');
  const [dataId, setDataId] = useState('');
  const [hashuuid, setHash] = useState('');
  const [hashOwnerId, setHashOwnerId] = useState('');
  const [atBlock, setBlockNumber] = useState('');
  const [quoteRA, setQuoteRA] = useState('');
  const [pkd, setPKD] = useState('');
  const [transactionReceipt, setTransactionReceipt] = useState(null);
  const [transactionReceiptAccessRequest, setTransactionReceiptAccessRequest] = useState(null);
  const [transactionResult, setTransactionResult] = useState(null);
  const [transactionResultAddAccess, setTransactionResultAddAccess] = useState(null);
  const [inputValue, setInputValue] = useState('');
  const [inputValueAccess, setInputValueAccess] = useState('');
  const [authorizedList, setAuthorizedList] = useState([]);

  useEffect(() => {
    const loadBlockchainData = async () => {
      try {
        const web3 = new Web3(Web3.givenProvider || "http://127.0.0.1:7545");
        setWeb3(web3)

        const accounts = await web3.eth.getAccounts();
        setAccounts(accounts);

        const contractABI = [
          {
            "anonymous": false,
            "inputs": [
              {
                "indexed": false,
                "internalType": "uint256",
                "name": "_reqBlockID",
                "type": "uint256"
              },
              {
                "indexed": false,
                "internalType": "bool",
                "name": "_isSuccess",
                "type": "bool"
              }
            ],
            "name": "AddAccess",
            "type": "event"
          },
          {
            "anonymous": false,
            "inputs": [
              {
                "indexed": true,
                "internalType": "bytes32",
                "name": "_dataID",
                "type": "bytes32"
              },
              {
                "indexed": false,
                "internalType": "bool",
                "name": "success",
                "type": "bool"
              }
            ],
            "name": "AddData",
            "type": "event"
          },
          {
            "anonymous": false,
            "inputs": [
              {
                "indexed": false,
                "internalType": "uint256",
                "name": "_assertionBlockID",
                "type": "uint256"
              },
              {
                "indexed": false,
                "internalType": "bool",
                "name": "_isSuccess",
                "type": "bool"
              }
            ],
            "name": "AttestAccessLog",
            "type": "event"
          },
          {
            "constant": false,
            "inputs": [
              {
                "internalType": "bytes32",
                "name": "_dataID",
                "type": "bytes32"
              },
              {
                "internalType": "bytes32",
                "name": "_ownerID",
                "type": "bytes32"
              },
              {
                "internalType": "bytes32",
                "name": "_pkData",
                "type": "bytes32"
              },
              {
                "internalType": "bytes32",
                "name": "_quoteRA",
                "type": "bytes32"
              },
              {
                "internalType": "bytes32[]",
                "name": "_authorizedList",
                "type": "bytes32[]"
              }
            ],
            "name": "addDataEntry",
            "outputs": [
              {
                "internalType": "bool",
                "name": "success",
                "type": "bool"
              }
            ],
            "payable": false,
            "stateMutability": "nonpayable",
            "type": "function"
          },
          {
            "constant": false,
            "inputs": [
              {
                "internalType": "bytes32",
                "name": "_requesterID",
                "type": "bytes32"
              },
              {
                "internalType": "bytes32",
                "name": "_dataID",
                "type": "bytes32"
              },
              {
                "internalType": "bytes32",
                "name": "_JWT",
                "type": "bytes32"
              },
              {
                "internalType": "bytes32",
                "name": "_reqWalletPK",
                "type": "bytes32"
              }
            ],
            "name": "addAccessRequest",
            "outputs": [
              {
                "internalType": "uint256",
                "name": "_reqBlockID",
                "type": "uint256"
              },
              {
                "internalType": "bool",
                "name": "_isSuccess",
                "type": "bool"
              }
            ],
            "payable": false,
            "stateMutability": "nonpayable",
            "type": "function"
          },
          {
            "constant": true,
            "inputs": [
              {
                "internalType": "bytes32",
                "name": "_dataID",
                "type": "bytes32"
              },
              {
                "internalType": "bytes32",
                "name": "_requesterID",
                "type": "bytes32"
              }
            ],
            "name": "verifyAuthList",
            "outputs": [
              {
                "internalType": "bool",
                "name": "auth",
                "type": "bool"
              }
            ],
            "payable": false,
            "stateMutability": "view",
            "type": "function"
          },
          {
            "constant": false,
            "inputs": [
              {
                "internalType": "bytes32",
                "name": "_dataID",
                "type": "bytes32"
              },
              {
                "internalType": "uint256",
                "name": "_reqBlockID",
                "type": "uint256"
              },
              {
                "internalType": "bytes32",
                "name": "_quoteRA",
                "type": "bytes32"
              },
              {
                "internalType": "bytes32",
                "name": "_reqBlockHash",
                "type": "bytes32"
              }
            ],
            "name": "accessLogAssertion",
            "outputs": [
              {
                "internalType": "uint256",
                "name": "_assertionBlockID",
                "type": "uint256"
              },
              {
                "internalType": "bool",
                "name": "_isSuccess",
                "type": "bool"
              }
            ],
            "payable": false,
            "stateMutability": "nonpayable",
            "type": "function"
          },
          {
            "constant": true,
            "inputs": [
              {
                "internalType": "uint256",
                "name": "_requestID",
                "type": "uint256"
              }
            ],
            "name": "readAccessLog",
            "outputs": [
              {
                "internalType": "bytes32",
                "name": "_requester",
                "type": "bytes32"
              },
              {
                "internalType": "uint256",
                "name": "_accessTime",
                "type": "uint256"
              },
              {
                "internalType": "bytes32",
                "name": "_dataID",
                "type": "bytes32"
              },
              {
                "internalType": "bool",
                "name": "_isSuccess",
                "type": "bool"
              }
            ],
            "payable": false,
            "stateMutability": "view",
            "type": "function"
          }
        ];
        const contractAddress = '0xfe77Aa9Dc4EE346Fb4aC98d28050DCD7D95E3082';
        const contract = new web3.eth.Contract(contractABI, contractAddress);
        setContract(contract);

      } catch (error) {
        console.error('Error occurred:', error);
        setError(`Blockchain interaction failed: ${error.message}`);
      }
    };

    loadBlockchainData();
  }, []);

  const generateUUID = async () => {
    const newUuid = uuidv4();
    setDataId(newUuid);
    const hashedUuid = CryptoJS.SHA256(newUuid).toString(CryptoJS.enc.Hex);
    const bytes32Hash = '0x' + hashedUuid;
    setHash(bytes32Hash);

    const parsedUser = inputValue.split(',').map(item => item.trim());
    const hashedAuthrisedList = hashItems(parsedUser);
    setAuthorizedList(hashedAuthrisedList);

    setHashOwnerId(hashVal(ownerId));

    console.log(`UUID: ${newUuid}, Hash: ${bytes32Hash}`);
    console.log(hashedAuthrisedList)

    try {
      const response = await axios.post('http://127.0.0.1:8080/data', { dataId: bytes32Hash });
      setResponse(response.data.message);

      if (response.data.quoteRA) {
        const hashedQuoteRA = hashVal(response.data.quoteRA);
        setQuoteRA(hashedQuoteRA);
        console.log(`Hashed quoteRA: ${hashedQuoteRA}`);
      } else {
        console.error('quoteRA not found in the response');
      }

      if (response.data.pkd) {
        const hashedPKD = hashVal(response.data.pkd);
        setPKD(hashedPKD);
        console.log(`Hashed Public key: ${hashedPKD}`);
      } else {
        console.error('pkd not found in the response');
      }
    } catch (error) {
      console.error('Error during UUID generation and data fetch:', error);
      setError('Failed to generate UUID or fetch data');
    }
  };

  const addEntry = async () => {
    try {
      const receipt = await contract.methods.addDataEntry(hashuuid, hashOwnerId, pkd, quoteRA, authorizedList)
        .send({ from: accounts[0], gas: 3000000 });
      console.log('Transaction receipt:', receipt);
      setTransactionReceipt(receipt);

      if (receipt.events.AddData) {
        const eventData = receipt.events.AddData.returnValues;
        setTransactionResult(`Return hashed data ID: ${eventData._dataID}, Transaction successful: ${eventData.success}`);
      }

      const block = await web3.eth.getBlockNumber();
      setBlockNumber(block);
      console.log(block);
    } catch (error) {
      console.error('Error occurred:', error);
      setError(`Blockchain interaction failed: ${error.message}`);
    }
  }

  const accessRequest = async () => {
    try {
      const hashedRequesterId = hashVal(requester);
      const hashedInputDataId = hashVal(inputValueAccess);
      const hashedJWT = hashVal(hardcodeJWT);
      console.log(hashedInputDataId);
      console.log('Hashed Account:', web3.utils.padLeft(accounts[0], 64));
      const receipt = await contract.methods.addAccessRequest(hashedRequesterId, hashedInputDataId, hashedJWT, web3.utils.padLeft(accounts[0], 64))
        .send({ from: accounts[0], gas: 3000000 });
      console.log('Transaction receipt:', receipt);
      setTransactionReceiptAccessRequest(receipt);

      if (receipt.events.AddAccess) {
        setTransactionResultAddAccess(`Request Block ID: ${receipt.events.AddAccess.returnValues._reqBlockID}, Success: ${receipt.events.AddAccess.returnValues._isSuccess}`);
        console.log(receipt.blockHash);
        try {
          const response = await axios.post('http://127.0.0.1:8080/access', { blockhash: receipt.blockHash });
          setResponseBlockHash(response.data.blockhash);
        
        } catch (error) {
          console.error(error);
          setError('Failed to access the pass');
        }
      }
    } catch (error) {
      console.error('Error occurred:', error);
      setError(`Blockchain interaction failed: ${error.message}`);
    }
  }

  const hashVal = (value) => {
    const hashedValue = CryptoJS.SHA256(value).toString();
    return '0x' + hashedValue;
  };

  const hashItems = (items) => {
    const hashedItems = items.map(item => '0x' + CryptoJS.SHA256(item).toString(CryptoJS.enc.Hex));
    return hashedItems;
  }

  const handleInputChange = (event) => {
    setInputValue(event.target.value);
  };

  const handleAccessChange = (event) => {
    setInputValueAccess(event.target.value);
  };

  return (
    <div>
      <h1>Your Id: {ownerId}</h1>
      <div>
        <input
          type="text"
          value={inputValue}
          onChange={handleInputChange}
          placeholder="Enter authrised user"
        />
        <button onClick={generateUUID}>Request</button>
      </div>
      <button onClick={addEntry}>Add Entry</button>
      <p>Registed at: {atBlock.toString()}</p>
      <p>Data Id: {dataId}</p>
      <p>Transaction receipt: {transactionReceipt ? transactionReceipt.transactionHash : 'No transaction yet'}</p>
      {transactionResult && <p>{transactionResult}</p>}
      {error && <p>Error: {error}</p>}
      <div>
        <h1>{requester}</h1>
        <input
          type="text"
          value={inputValueAccess}
          onChange={handleAccessChange}
          placeholder="Which data you want to access"
        />
        <button onClick={accessRequest}>Access</button>
        <p>Transaction receipt: {transactionReceiptAccessRequest ? transactionReceiptAccessRequest.transactionHash : 'No access request transaction yet'}</p>
        {transactionResultAddAccess && <p>{transactionResultAddAccess}</p>}
        {error && <p>Error: {error}</p>}
      </div>
    </div>
  );
}

export default App;
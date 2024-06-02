pragma solidity >=0.4.22 <0.6.0;

contract DataEscrow {
    //define constant: enclave wallet public key hardcoded
    bytes32 constant enclaveWalletPK = "d439730b8e59401b9adb42a79f93bd52";

    // data registration data struct
    bytes32 dataID;
    struct EscrowData {
        bytes32 ownerID;
        bytes32 pkData;
        bytes32 quoteRA;
        bytes32[] authorizedList;
    }
    mapping(bytes32 => EscrowData) dataEntry;

    //Requester's access request log data struct
    uint reqBlockID;
    struct AccessRequest {
        bytes32 requesterID;
        bytes32 dataID;
        bytes32 JWT;
        bytes32 reqWalletPK;
        uint accessTime;
        bool isSuccess;
    }
    mapping(uint => AccessRequest) accessLog;

    //SGX access log assertion data struct
    uint assertionBlockID;
    struct AccessAssertion {
        bytes32 dataID;
        uint reqBlockID;
        bytes32 quoteRA;
        bytes32 reqBlockHash;
    }
    mapping(uint => AccessAssertion) enclaveVerified;

    event AddData(bytes32 indexed _dataID, bool success);
    event AddAccess(uint _reqBlockID, bool _isSuccess);
    event AttestAccessLog(uint _assertionBlockID, bool _isSuccess);

    function addDataEntry(
        bytes32 _dataID,
        bytes32 _ownerID,
        bytes32 _pkData,
        bytes32 _quoteRA,
        bytes32[] memory _authorizedList
    ) public returns (bool success) {
        EscrowData memory owner = EscrowData(
            _ownerID,
            _pkData,
            _quoteRA,
            _authorizedList
        );
        dataEntry[_dataID] = owner;
        emit AddData(_dataID, true);
        return true;
    }

    function addAccessRequest(
        bytes32 _requesterID,
        bytes32 _dataID,
        bytes32 _JWT,
        bytes32 _reqWalletPK
    ) public returns (uint _reqBlockID, bool _isSuccess) {
        //check if the dataID is valid
        require(dataEntry[_dataID].ownerID != 0, "dataID does not exists");
        bool accessAllow = false;
        //verify requester is in ACL
        if (verifyAuthList(_dataID, _requesterID) == true) {
            // add accessAllow success if the requester is authorized
            accessAllow = true;
        }
        AccessRequest memory access = AccessRequest(
            _requesterID,
            _dataID,
            _JWT,
            _reqWalletPK,
            now,
            accessAllow
        );
        reqBlockID = block.number;
        accessLog[reqBlockID] = access;
        emit AddAccess(reqBlockID, accessAllow);
        return (reqBlockID, accessAllow);
    }

    function verifyAuthList(
        bytes32 _dataID,
        bytes32 _requesterID
    ) public view returns (bool auth) {
        // getAuthList
        bytes32[] memory authList = dataEntry[_dataID].authorizedList;
        // verify if request is in authList
        for (uint i = 0; i < authList.length; i++) {
            bytes32 authID = authList[i];
            if (authID == _requesterID) {
                return true; //mathed
            }
        }
        return false; //no match
    }

    function accessLogAssertion(
        bytes32 _dataID,
        uint _reqBlockID,
        bytes32 _quoteRA,
        bytes32 _reqBlockHash
    ) public returns (uint _assertionBlockID, bool _isSuccess) {
        //obtain blockhash with block ID and compare the hash sent by proxy
        require(
            blockhash(_reqBlockID) == _reqBlockHash,
            "Access request is not valid!"
        );
        //Add attestation
        AccessAssertion memory assertion = AccessAssertion(
            _dataID,
            _reqBlockID,
            _quoteRA,
            _reqBlockHash
        );
        assertionBlockID = block.number;
        enclaveVerified[assertionBlockID] = assertion;
        emit AttestAccessLog(assertionBlockID, true);
        return (reqBlockID, true);
    }

    function readAccessLog(
        uint _requestID
    )
        public
        view
        returns (
            bytes32 _requester,
            uint _accessTime,
            bytes32 _dataID,
            bool _isSuccess
        )
    {
        //check if requestID exists
        if (accessLog[_requestID].requesterID == 0) {
            revert("requestID does not exist!");
        }
        // get AccessRequest stuct
        AccessRequest memory access = accessLog[_requestID];
        return (
            access.requesterID,
            access.accessTime,
            access.dataID,
            access.isSuccess
        );
    }
}

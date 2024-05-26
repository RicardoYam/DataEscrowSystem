const DataEscrow = artifacts.require("DataEscrow");

module.exports = function(deployer) {
  deployer.deploy(DataEscrow);
};

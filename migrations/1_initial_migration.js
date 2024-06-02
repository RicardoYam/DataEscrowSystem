const Migrations = artifacts.require("DataEscrow");

module.exports = function(deployer) {
  deployer.deploy(Migrations);
};

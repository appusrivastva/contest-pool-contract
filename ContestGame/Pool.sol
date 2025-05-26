// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

/// @title Contest Pool Contract for managing contests and winners
/// @author
/// @notice This contract allows contest creators to create contests, users to join by paying entry fees,
/// end contests, discard if soft cap not reached, claim refunds, and declare winners with off-chain signature verification.
contract ContestPool is ReentrancyGuard, Ownable {
    using ECDSA for bytes32;
    using SafeERC20 for IERC20;

    /// @notice Platform fee percentage taken from total collected funds (default 2%)
    uint256 public PLATFORM_FEE = 2;

    /// @notice ERC20 token used for entry fees and rewards
    IERC20 public plt;

    /// @notice Event emitted when a contest is created
    event CreateContest(
        string indexed contestName,
        uint256 entryFee,
        uint256 maxParticipant,
        uint256 contestId,
        address creator
    );

    /// @notice Event emitted when a user joins a contest
    event JoinContest(address indexed userAddress, uint256 contestId);

    /// @notice Event emitted when a contest is ended by creator
    event EndContest(address indexed contestOwner, uint256 contestId);

    /// @notice Event emitted when a winner is declared and rewarded
    event WinnerDeclared(address indexed userAddress, uint256 amount);

    /// @notice Event emitted when a contest is discarded by creator
    event ContestDiscarded(uint256 indexed contestId);

    /// @notice Event emitted when a participant claims refund after contest discard
    event RefundClaimed(uint256 indexed contestId, address indexed user);

    /// @notice Contest struct containing all details about a contest
    struct Contest {
        uint256 contestId;
        uint256 entryFee;
        uint256 maxParticipant;
        address creatorAddress;
        address[] allJoinUsers;
        mapping(address => bool) hasJoined;
        bool isActive;
        string contestName;
        uint256 startTime;
        uint256 endTime;
        string description;
        uint256 totalUsers;
        address winner;
        uint256 prizePool;
        uint256 totalDeposit;
        uint256 softCap;
        bool isDiscarded;
        bool isRewardDistributed;
        uint256 totalWithdraw;
        bool isClaimed;
        mapping(address => bool) refunded;
    }

    /// @notice Mapping from contest ID to Contest struct
    mapping(uint256 => Contest) private contests;

    /// @notice Mapping from creator address to list of contest IDs created by them
    mapping(address => uint256[]) public allContests;

    /// @notice Total number of contests created
    uint256 public totalContest;

    /// @notice Modifier to restrict function to contest creator only
    /// @param contestId Contest identifier
    modifier onlyContestCreator(uint256 contestId) {
        require(
            msg.sender == contests[contestId].creatorAddress,
            "Not contest creator"
        );
        _;
    }

    /// @notice Constructor initializes the token address for platform token
    /// @param _pltAddress ERC20 token address used for fees and rewards
    constructor(address _pltAddress) Ownable(msg.sender) {
        require(_pltAddress != address(0), "Invalid token address");
        plt = IERC20(_pltAddress);
    }

    /// @notice Creates a new contest
    /// @param _entryFee Entry fee for joining the contest
    /// @param _maxParticipant Maximum number of participants allowed
    /// @param contestDesc Description of the contest
    /// @param name Name of the contest
    /// @param _softCap Minimum total deposit required to consider contest successful
    function createContest(
        uint256 _entryFee,
        uint256 _maxParticipant,
        string memory contestDesc,
        string memory name,
        uint256 _softCap
    ) external nonReentrant {
        require(_maxParticipant > 0, "Max participant must be > 0");
        require(_entryFee > 0, "Entry fee must be > 0");

        totalContest++;
        Contest storage newContest = contests[totalContest];
        newContest.contestName = name;
        newContest.entryFee = _entryFee;
        newContest.maxParticipant = _maxParticipant;
        newContest.creatorAddress = msg.sender;
        newContest.startTime = block.timestamp;
        newContest.endTime = block.timestamp + 6 * 60 * 60; // 6 hours duration
        newContest.isActive = true;
        newContest.description = contestDesc;
        newContest.contestId = totalContest;
        newContest.softCap = _softCap;

        allContests[msg.sender].push(totalContest);

        emit CreateContest(
            name,
            _entryFee,
            _maxParticipant,
            totalContest,
            msg.sender
        );
    }

    /// @notice Allows a user to join an active contest by paying entry fee
    /// @param _contestId Contest ID to join
    function joinContest(uint256 _contestId) external nonReentrant {
        Contest storage contest = contests[_contestId];

        require(contest.isActive, "Contest is not active");
        require(
            block.timestamp >= contest.startTime,
            "Contest not started yet"
        );
        require(block.timestamp <= contest.endTime, "Contest is over");
        require(!contest.hasJoined[msg.sender], "Already joined");
        require(
            contest.totalUsers < contest.maxParticipant,
            "Max participants reached"
        );

        plt.safeTransferFrom(msg.sender, address(this), contest.entryFee);

        contest.totalUsers++;
        contest.hasJoined[msg.sender] = true;
        contest.allJoinUsers.push(msg.sender);
        contest.totalDeposit += contest.entryFee;

        emit JoinContest(msg.sender, _contestId);
    }

    /// @notice Calculates platform fee and prize pool for a contest
    /// @param _contestId Contest ID
    /// @return platformFee Amount of platform fee
    /// @return prizePool Amount available for prize distribution
    function calculatePrizePool(uint256 _contestId)
        internal
        view
        returns (uint256 platformFee, uint256 prizePool)
    {
        Contest storage contest = contests[_contestId];

        uint256 totalCollected = contest.totalUsers * contest.entryFee;
        platformFee = (totalCollected * PLATFORM_FEE) / 100;
        prizePool = totalCollected - platformFee;
    }

    /// @notice Allows contest creator to discard a contest if soft cap not reached after contest ended
    /// @param _contestId Contest ID to discard
    function discardContest(uint256 _contestId)
        external
        nonReentrant
        onlyContestCreator(_contestId)
    {
        Contest storage contest = contests[_contestId];

        require(contest.isActive, "Contest not active");
        require(block.timestamp > contest.endTime, "Contest not ended yet");
        require(contest.totalDeposit < contest.softCap, "Soft cap reached");

        contest.isActive = false;
        contest.isDiscarded = true;

        emit ContestDiscarded(_contestId);
    }

    /// @notice Ends a contest if conditions are met and transfers platform fee to contract owner
    /// @param _contestId Contest ID to end
    function endContest(uint256 _contestId)
        external
        nonReentrant
        onlyContestCreator(_contestId)
    {
        Contest storage contest = contests[_contestId];

        require(contest.isActive, "Contest not active");
        require(!contest.isDiscarded, "Contest discarded");
        require(block.timestamp > contest.endTime, "Contest not ended");
        require(
            contest.totalDeposit >= contest.softCap,
            "Soft cap not reached"
        );

        contest.isActive = false;

        (uint256 fee, uint256 rewardPool) = calculatePrizePool(_contestId);
        contest.prizePool = rewardPool;

        // Transfer platform fee to contract owner
        plt.safeTransfer(owner(), fee);

        emit EndContest(msg.sender, _contestId);
    }

    /// @notice Allows participants to claim refund if contest was discarded
    /// @param _contestId Contest ID for which to claim refund
    function claimRefund(uint256 _contestId) external nonReentrant {
        Contest storage contest = contests[_contestId];

        require(contest.isDiscarded, "Contest not discarded");
        require(contest.hasJoined[msg.sender], "Did not join contest");
        require(!contest.refunded[msg.sender], "Already refunded");

        contest.refunded[msg.sender] = true;

        plt.safeTransfer(msg.sender, contest.entryFee);

        emit RefundClaimed(_contestId, msg.sender);
    }

    /// @notice Updates platform fee percentage (max 10%)
    /// @param _fee New platform fee percentage
    function updatePlatformFee(uint256 _fee) external onlyOwner nonReentrant {
        require(_fee <= 10, "Fee too high");
        PLATFORM_FEE = _fee;
    }

    /// @notice Declares winner and transfers prize reward, verified by off-chain signature
    /// @param poolId Contest ID
    /// @param winner Winner's address
    /// @param _signature Off-chain signature by contest creator
    /// @param amount Amount to transfer to winner
    function declareWinner(
        uint256 poolId,
        address winner,
        bytes memory _signature,
        uint256 amount
    ) external nonReentrant onlyContestCreator(poolId) {
        Contest storage pool = contests[poolId];

        require(!pool.isActive, "Contest still active");
        require(
            amount <= (pool.totalDeposit - pool.totalWithdraw),
            "Invalid amount"
        );
        require(!pool.isClaimed, "Prize already claimed");

        bytes32 messageHash = getMessageHash(poolId, winner, amount);
        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(
            messageHash
        );

        require(
            SignatureChecker.isValidSignatureNow(
                pool.creatorAddress,
                ethSignedMessageHash,
                _signature
            ),
            "Invalid signature"
        );

        pool.isClaimed = true;
        pool.winner = winner;
        pool.totalWithdraw += amount;

        plt.safeTransfer(winner, amount);

        emit WinnerDeclared(winner, amount);
    }

    /// @notice Returns hash of the message used for signature verification
    /// @param poolId Contest ID
    /// @param winner Winner address
    /// @param amount Prize amount
    /// @return hash Message hash
    function getMessageHash(
        uint256 poolId,
        address winner,
        uint256 amount
    ) public pure returns (bytes32 hash) {
        return keccak256(abi.encode(poolId, winner, amount));
    }

    function getContestBasicInfo(uint256 contestId)
        external
        view
        returns (
            uint256 id,
            uint256 entryFee,
            uint256 maxParticipant,
            address creator,
            bool active,
            string memory contestName,
            uint256 startTime,
            uint256 endTime,
            string memory description,
            uint256 totalUsers,
            address winner,
            uint256 prizePool,
            uint256 totalDeposit,
            uint256 softCap,
            bool isDiscarded,
            bool isClaimed
        )
    {
        Contest storage contest = contests[contestId];
        return (
            contest.contestId,
            contest.entryFee,
            contest.maxParticipant,
            contest.creatorAddress,
            contest.isActive,
            contest.contestName,
            contest.startTime,
            contest.endTime,
            contest.description,
            contest.totalUsers,
            contest.winner,
            contest.prizePool,
            contest.totalDeposit,
            contest.softCap,
            contest.isDiscarded,
            contest.isClaimed
        );
    }

    /// @notice Returns list of users who joined a contest
    /// @param contestId Contest ID
    /// @return users Array of participant addresses
    function getAllParticipants(uint256 contestId)
        external
        view
        returns (address[] memory users)
    {
        return contests[contestId].allJoinUsers;
    }

    /// @notice Checks if a user has joined a contest
    /// @param contestId Contest ID
    /// @param user User address
    /// @return joined True if user joined
    function hasUserJoined(uint256 contestId, address user)
        external
        view
        returns (bool joined)
    {
        return contests[contestId].hasJoined[user];
    }
}

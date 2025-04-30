;; hiveguard-core
;; 
;; This contract serves as the central hub for HiveGuard DAO operations, handling everything
;; from DAO initialization to ongoing governance. It manages membership records with different
;; role types, tracks proposal creation and lifecycle, counts votes, and executes approved
;; proposals. The contract includes comprehensive security features and treasury management
;; capabilities.

;; =============================
;; Constants and Error Codes
;; =============================

;; General Errors
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-DAO-NOT-INITIALIZED (err u101))
(define-constant ERR-DAO-ALREADY-INITIALIZED (err u102))
(define-constant ERR-INVALID-PARAMETER (err u103))

;; Membership Errors
(define-constant ERR-MEMBER-NOT-FOUND (err u200))
(define-constant ERR-MEMBER-ALREADY-EXISTS (err u201))
(define-constant ERR-INVALID-ROLE (err u202))
(define-constant ERR-CANNOT-REMOVE-SELF (err u203))
(define-constant ERR-DELEGATE-NOT-AUTHORIZED (err u204))

;; Proposal Errors
(define-constant ERR-PROPOSAL-NOT-FOUND (err u300))
(define-constant ERR-PROPOSAL-ALREADY-EXISTS (err u301))
(define-constant ERR-PROPOSAL-EXPIRED (err u302))
(define-constant ERR-PROPOSAL-NOT-ACTIVE (err u303))
(define-constant ERR-ALREADY-VOTED (err u304))
(define-constant ERR-VOTING-PERIOD-ENDED (err u305))
(define-constant ERR-VOTING-PERIOD-NOT-ENDED (err u306))
(define-constant ERR-PROPOSAL-ALREADY-EXECUTED (err u307))
(define-constant ERR-PROPOSAL-REJECTED (err u308))
(define-constant ERR-INSUFFICIENT-QUORUM (err u309))

;; Treasury Errors
(define-constant ERR-INSUFFICIENT-FUNDS (err u400))
(define-constant ERR-TRANSFER-FAILED (err u401))
(define-constant ERR-TIMELOCK-ACTIVE (err u402))
(define-constant ERR-MULTISIG-REQUIRED (err u403))
(define-constant ERR-INVALID-ASSET (err u404))

;; Role Types
(define-constant ROLE-ADMIN u1)
(define-constant ROLE-MEMBER u2)
(define-constant ROLE-DELEGATE u3)

;; Proposal Status
(define-constant STATUS-ACTIVE u1)
(define-constant STATUS-PASSED u2)
(define-constant STATUS-REJECTED u3)
(define-constant STATUS-EXECUTED u4)
(define-constant STATUS-EXPIRED u5)

;; Vote Types
(define-constant VOTE-FOR u1)
(define-constant VOTE-AGAINST u2)
(define-constant VOTE-ABSTAIN u3)

;; Multisig threshold default (percentage requiring approval, 80 = 80%)
(define-constant DEFAULT-MULTISIG-THRESHOLD u80)

;; Default timelock duration in blocks (approximately 1 day at 10 min block times)
(define-constant DEFAULT-TIMELOCK-BLOCKS u144)

;; Default voting period duration in blocks (approximately 1 week)
(define-constant DEFAULT-VOTING-PERIOD-BLOCKS u1008)

;; Default quorum percentage (minimum participation required, 25 = 25%)
(define-constant DEFAULT-QUORUM-PERCENTAGE u25)

;; =============================
;; Data Maps and Variables
;; =============================

;; DAO Configuration
(define-data-var dao-initialized bool false)
(define-data-var dao-name (string-ascii 100) "")
(define-data-var dao-description (string-utf8 500) u"")
(define-data-var dao-creator principal 'ST000000000000000000000000000000000000000000)
(define-data-var dao-creation-height uint u0)
(define-data-var dao-metadata (optional (string-utf8 1000)) none)

;; Governance Parameters
(define-data-var voting-period-blocks uint DEFAULT-VOTING-PERIOD-BLOCKS)
(define-data-var quorum-percentage uint DEFAULT-QUORUM-PERCENTAGE)
(define-data-var timelock-blocks uint DEFAULT-TIMELOCK-BLOCKS)
(define-data-var multisig-threshold uint DEFAULT-MULTISIG-THRESHOLD)
(define-data-var high-value-threshold uint u1000000000) ;; 1000 STX by default
(define-data-var total-members uint u0)

;; Members and Roles
;; Maps principal to role (admin, member, delegate)
(define-map members principal 
  {
    role: uint,
    joined-at-block: uint,
    voting-power: uint,
    metadata: (optional (string-utf8 500))
  }
)

;; Delegation relationships
(define-map delegations
  { delegator: principal }
  { delegate: principal, active: bool, created-at-block: uint }
)

;; Proposals
(define-map proposals
  uint ;; proposal-id
  {
    creator: principal,
    title: (string-ascii 100),
    description: (string-utf8 2000),
    created-at-block: uint,
    expires-at-block: uint,
    status: uint,
    yes-votes: uint,
    no-votes: uint,
    abstain-votes: uint,
    executed-at-block: (optional uint),
    execution-delay: uint, ;; additional timelock beyond voting period
    target-contract: (optional principal),
    target-function: (optional (string-ascii 128)),
    target-args: (optional (list 20 (string-utf8 500))),
    has-metadata: bool
  }
)

;; Proposal metadata for extended information
(define-map proposal-metadata
  uint ;; proposal-id
  { 
    details-uri: (optional (string-utf8 500)),
    additional-info: (optional (string-utf8 1000))
  }
)

;; Votes cast
(define-map votes
  { proposal-id: uint, voter: principal }
  { vote-type: uint, weight: uint, voted-at-block: uint }
)

;; Treasury assets
(define-map treasury-assets
  { asset-contract: principal, asset-name: (string-ascii 128) }
  { balance: uint, last-updated-block: uint }
)

;; Timelock tracker for high-value operations
(define-map timelock-operations
  uint ;; operation-id
  {
    initiator: principal, 
    proposal-id: uint,
    unlock-height: uint,
    target-contract: principal,
    target-function: (string-ascii 128),
    target-args: (list 20 (string-utf8 500)),
    executed: bool
  }
)

;; Multisig approvals for high-value operations
(define-map multisig-approvals
  { operation-id: uint, approver: principal }
  { approved: bool, approved-at-block: uint }
)

;; Counters for IDs
(define-data-var next-proposal-id uint u1)
(define-data-var next-operation-id uint u1)
(define-data-var proposal-count uint u0)
(define-data-var executed-proposal-count uint u0)

;; =============================
;; Private Functions
;; =============================

;; Check if DAO is initialized
(define-private (is-dao-initialized)
  (var-get dao-initialized)
)

;; Check if caller is an admin
(define-private (is-admin (caller principal))
  (match (map-get? members caller)
    admin-entry (is-eq (get role admin-entry) ROLE-ADMIN)
    false
  )
)

;; Check if caller is a member (includes admins)
(define-private (is-member (caller principal))
  (match (map-get? members caller)
    member-entry (or 
                   (is-eq (get role member-entry) ROLE-ADMIN)
                   (is-eq (get role member-entry) ROLE-MEMBER)
                 )
    false
  )
)

;; Check if a principal is authorized to vote (either directly or via delegation)
(define-private (can-vote (voter principal))
  (if (is-member voter)
    true
    (match (map-get? delegations { delegator: voter })
      delegation (get active delegation) 
      false)
  )
)

;; Get the effective voter (original principal or their delegate if delegation is active)
(define-private (get-effective-voter (voter principal))
  (match (map-get? delegations { delegator: voter })
    delegation (if (get active delegation)
                  (get delegate delegation)
                  voter)
    voter)
)

;; Get voting power for a member
(define-private (get-voting-power (member principal))
  (match (map-get? members member)
    member-entry (get voting-power member-entry)
    u0)
)

;; Check if proposal exists
(define-private (proposal-exists (proposal-id uint))
  (is-some (map-get? proposals proposal-id))
)

;; Check if proposal is still active
(define-private (is-proposal-active (proposal-id uint))
  (match (map-get? proposals proposal-id)
    proposal (is-eq (get status proposal) STATUS-ACTIVE)
    false)
)

;; Check if voting period has ended for a proposal
(define-private (has-voting-ended (proposal-id uint))
  (match (map-get? proposals proposal-id)
    proposal (>= block-height (get expires-at-block proposal))
    true)
)

;; Check if a proposal has met quorum
(define-private (has-met-quorum (proposal-id uint))
  (match (map-get? proposals proposal-id)
    proposal 
    (let ((total-votes (+ (+ (get yes-votes proposal) (get no-votes proposal)) (get abstain-votes proposal)))
          (required-votes (/ (* (var-get total-members) (var-get quorum-percentage)) u100)))
      (>= total-votes required-votes))
    false)
)

;; Check if a proposal has passed (has more yes than no votes and meets quorum)
(define-private (has-proposal-passed (proposal-id uint))
  (match (map-get? proposals proposal-id)
    proposal 
    (and 
      (has-met-quorum proposal-id)
      (> (get yes-votes proposal) (get no-votes proposal)))
    false)
)

;; Calculate proposal expiration block
(define-private (calculate-expiration-block)
  (+ block-height (var-get voting-period-blocks))
)

;; Calculate timelock expiration for high-value operations
(define-private (calculate-timelock-expiration)
  (+ block-height (var-get timelock-blocks))
)

;; Increment proposal counter and get next ID
(define-private (get-next-proposal-id)
  (let ((current-id (var-get next-proposal-id)))
    (var-set next-proposal-id (+ current-id u1))
    (var-set proposal-count (+ (var-get proposal-count) u1))
    current-id)
)

;; Increment operation counter and get next ID
(define-private (get-next-operation-id)
  (let ((current-id (var-get next-operation-id)))
    (var-set next-operation-id (+ current-id u1))
    current-id)
)

;; Update proposal status
(define-private (update-proposal-status (proposal-id uint) (new-status uint))
  (match (map-get? proposals proposal-id)
    proposal 
    (map-set proposals 
      proposal-id
      (merge proposal { status: new-status }))
    false)
)

;; Record proposal execution
(define-private (record-proposal-execution (proposal-id uint))
  (match (map-get? proposals proposal-id)
    proposal 
    (begin
      (map-set proposals 
        proposal-id
        (merge proposal { 
          status: STATUS-EXECUTED,
          executed-at-block: (some block-height) 
        }))
      (var-set executed-proposal-count (+ (var-get executed-proposal-count) u1))
      true)
    false)
)

;; Check timelock for high-value operations
(define-private (is-timelock-expired (operation-id uint))
  (match (map-get? timelock-operations operation-id)
    operation (>= block-height (get unlock-height operation))
    true)
)

;; Count multisig approvals for an operation
(define-private (count-multisig-approvals (operation-id uint))
  ;; In a real contract implementation, we would iterate through all admins
  ;; and count their approvals. For simplicity, we'll return a placeholder.
  ;; In production, you would track approvals separately.
  u0
)

;; Check if multisig requirements are met
(define-private (has-enough-multisig-approvals (operation-id uint))
  (let ((approval-count (count-multisig-approvals operation-id))
        (admin-count u5)) ;; Placeholder, in production would be tracked
    (>= (* approval-count u100) (* admin-count (var-get multisig-threshold)))
  )
)

;; Update treasury asset balance
(define-private (update-treasury-balance (asset-contract principal) (asset-name (string-ascii 128)) (amount uint))
  (let ((current-entry (map-get? treasury-assets { asset-contract: asset-contract, asset-name: asset-name })))
    (match current-entry
      entry (map-set treasury-assets 
              { asset-contract: asset-contract, asset-name: asset-name }
              { balance: (+ (get balance entry) amount), last-updated-block: block-height })
      (map-set treasury-assets
        { asset-contract: asset-contract, asset-name: asset-name }
        { balance: amount, last-updated-block: block-height }))
    true)
)

;; =============================
;; Read-Only Functions
;; =============================

;; Get DAO information
(define-read-only (get-dao-info)
  {
    initialized: (var-get dao-initialized),
    name: (var-get dao-name),
    description: (var-get dao-description),
    creator: (var-get dao-creator),
    creation-height: (var-get dao-creation-height),
    metadata: (var-get dao-metadata),
    total-members: (var-get total-members),
    proposal-count: (var-get proposal-count),
    executed-proposal-count: (var-get executed-proposal-count)
  }
)

;; Get governance parameters
(define-read-only (get-governance-params)
  {
    voting-period-blocks: (var-get voting-period-blocks),
    quorum-percentage: (var-get quorum-percentage),
    timelock-blocks: (var-get timelock-blocks),
    multisig-threshold: (var-get multisig-threshold),
    high-value-threshold: (var-get high-value-threshold)
  }
)

;; Get member details
(define-read-only (get-member (member-principal principal))
  (map-get? members member-principal)
)

;; Check if a principal is a member
(define-read-only (check-membership (user principal))
  (is-member user)
)

;; Check if a principal is an admin
(define-read-only (check-admin (user principal))
  (is-admin user)
)

;; Get delegation details
(define-read-only (get-delegation (delegator principal))
  (map-get? delegations { delegator: delegator })
)

;; Get proposal details
(define-read-only (get-proposal (proposal-id uint))
  (map-get? proposals proposal-id)
)

;; Get proposal metadata
(define-read-only (get-proposal-metadata (proposal-id uint))
  (map-get? proposal-metadata proposal-id)
)

;; Get proposal vote details
(define-read-only (get-vote (proposal-id uint) (voter principal))
  (map-get? votes { proposal-id: proposal-id, voter: voter })
)

;; Get proposal status
(define-read-only (get-proposal-status (proposal-id uint))
  (match (map-get? proposals proposal-id)
    proposal (get status proposal)
    u0)
)

;; Get treasury asset details
(define-read-only (get-treasury-asset (asset-contract principal) (asset-name (string-ascii 128)))
  (map-get? treasury-assets { asset-contract: asset-contract, asset-name: asset-name })
)

;; Get timelock operation details
(define-read-only (get-timelock-operation (operation-id uint))
  (map-get? timelock-operations operation-id)
)

;; =============================
;; Public Functions
;; =============================

;; Initialize the DAO
(define-public (initialize-dao 
  (name (string-ascii 100)) 
  (description (string-utf8 500))
  (metadata (optional (string-utf8 1000))))
  (let ((caller tx-sender))
    (asserts! (not (var-get dao-initialized)) ERR-DAO-ALREADY-INITIALIZED)
    
    ;; Set DAO parameters
    (var-set dao-initialized true)
    (var-set dao-name name)
    (var-set dao-description description)
    (var-set dao-creator caller)
    (var-set dao-creation-height block-height)
    (var-set dao-metadata metadata)
    
    ;; Add creator as the first admin
    (map-set members caller {
      role: ROLE-ADMIN,
      joined-at-block: block-height,
      voting-power: u100,
      metadata: none
    })
    
    ;; Increment member count
    (var-set total-members u1)
    
    (ok true))
)

;; Update governance parameters (admin only)
(define-public (update-governance-params
  (new-voting-period (optional uint))
  (new-quorum-percentage (optional uint))
  (new-timelock-blocks (optional uint))
  (new-multisig-threshold (optional uint))
  (new-high-value-threshold (optional uint)))
  (let ((caller tx-sender))
    ;; Validate permissions
    (asserts! (var-get dao-initialized) ERR-DAO-NOT-INITIALIZED)
    (asserts! (is-admin caller) ERR-NOT-AUTHORIZED)
    
    ;; Update parameters if provided
    (match new-voting-period period (var-set voting-period-blocks period) true)
    (match new-quorum-percentage quorum 
      (begin
        (asserts! (<= quorum u100) ERR-INVALID-PARAMETER)
        (var-set quorum-percentage quorum)
        true)
      true)
    (match new-timelock-blocks timelock (var-set timelock-blocks timelock) true)
    (match new-multisig-threshold threshold 
      (begin
        (asserts! (<= threshold u100) ERR-INVALID-PARAMETER)
        (var-set multisig-threshold threshold)
        true)
      true)
    (match new-high-value-threshold threshold (var-set high-value-threshold threshold) true)
    
    (ok true))
)

;; Add a new member (admin only)
(define-public (add-member 
  (new-member principal)
  (role uint)
  (voting-power uint)
  (metadata (optional (string-utf8 500))))
  (let ((caller tx-sender))
    ;; Validate input and permissions
    (asserts! (var-get dao-initialized) ERR-DAO-NOT-INITIALIZED)
    (asserts! (is-admin caller) ERR-NOT-AUTHORIZED)
    (asserts! (or (is-eq role ROLE-ADMIN) (is-eq role ROLE-MEMBER)) ERR-INVALID-ROLE)
    (asserts! (is-none (map-get? members new-member)) ERR-MEMBER-ALREADY-EXISTS)
    
    ;; Add the new member
    (map-set members new-member {
      role: role,
      joined-at-block: block-height,
      voting-power: voting-power,
      metadata: metadata
    })
    
    ;; Increment member count
    (var-set total-members (+ (var-get total-members) u1))
    
    (ok true))
)

;; Remove a member (admin only)
(define-public (remove-member (member-to-remove principal))
  (let ((caller tx-sender))
    ;; Validate input and permissions
    (asserts! (var-get dao-initialized) ERR-DAO-NOT-INITIALIZED)
    (asserts! (is-admin caller) ERR-NOT-AUTHORIZED)
    (asserts! (is-some (map-get? members member-to-remove)) ERR-MEMBER-NOT-FOUND)
    (asserts! (not (is-eq caller member-to-remove)) ERR-CANNOT-REMOVE-SELF)
    
    ;; Remove the member
    (map-delete members member-to-remove)
    
    ;; Also remove any active delegations
    (map-delete delegations { delegator: member-to-remove })
    
    ;; Decrement member count
    (var-set total-members (- (var-get total-members) u1))
    
    (ok true))
)

;; Update member role (admin only)
(define-public (update-member-role (member-principal principal) (new-role uint))
  (let ((caller tx-sender))
    ;; Validate input and permissions
    (asserts! (var-get dao-initialized) ERR-DAO-NOT-INITIALIZED)
    (asserts! (is-admin caller) ERR-NOT-AUTHORIZED)
    (asserts! (or (is-eq new-role ROLE-ADMIN) (is-eq new-role ROLE-MEMBER)) ERR-INVALID-ROLE)
    
    (match (map-get? members member-principal)
      member-entry (begin
        (map-set members 
          member-principal
          (merge member-entry { role: new-role }))
        (ok true))
      ERR-MEMBER-NOT-FOUND)
  )
)

;; Update member voting power (admin only)
(define-public (update-voting-power (member-principal principal) (new-voting-power uint))
  (let ((caller tx-sender))
    ;; Validate input and permissions
    (asserts! (var-get dao-initialized) ERR-DAO-NOT-INITIALIZED)
    (asserts! (is-admin caller) ERR-NOT-AUTHORIZED)
    
    (match (map-get? members member-principal)
      member-entry (begin
        (map-set members 
          member-principal
          (merge member-entry { voting-power: new-voting-power }))
        (ok true))
      ERR-MEMBER-NOT-FOUND)
  )
)

;; Delegate voting rights to another principal
(define-public (delegate-vote (delegate-to principal))
  (let ((caller tx-sender))
    ;; Validate input and permissions
    (asserts! (var-get dao-initialized) ERR-DAO-NOT-INITIALIZED)
    (asserts! (is-member caller) ERR-NOT-AUTHORIZED)
    
    ;; Create delegation
    (map-set delegations
      { delegator: caller }
      { delegate: delegate-to, active: true, created-at-block: block-height })
    
    (ok true))
)

;; Revoke delegation
(define-public (revoke-delegation)
  (let ((caller tx-sender))
    ;; Validate input and permissions
    (asserts! (var-get dao-initialized) ERR-DAO-NOT-INITIALIZED)
    
    (match (map-get? delegations { delegator: caller })
      delegation (begin
        (map-set delegations
          { delegator: caller }
          (merge delegation { active: false }))
        (ok true))
      ERR-MEMBER-NOT-FOUND)
  )
)

;; Create a new proposal
(define-public (create-proposal
  (title (string-ascii 100))
  (description (string-utf8 2000))
  (execution-delay uint)
  (target-contract (optional principal))
  (target-function (optional (string-ascii 128)))
  (target-args (optional (list 20 (string-utf8 500))))
  (details-uri (optional (string-utf8 500)))
  (additional-info (optional (string-utf8 1000))))
  (let ((caller tx-sender)
        (proposal-id (get-next-proposal-id))
        (expiration (calculate-expiration-block))
        (has-meta (or (is-some details-uri) (is-some additional-info))))
    
    ;; Validate input and permissions
    (asserts! (var-get dao-initialized) ERR-DAO-NOT-INITIALIZED)
    (asserts! (is-member caller) ERR-NOT-AUTHORIZED)
    
    ;; Create the proposal
    (map-set proposals
      proposal-id
      {
        creator: caller,
        title: title,
        description: description,
        created-at-block: block-height,
        expires-at-block: expiration,
        status: STATUS-ACTIVE,
        yes-votes: u0,
        no-votes: u0,
        abstain-votes: u0,
        executed-at-block: none,
        execution-delay: execution-delay,
        target-contract: target-contract,
        target-function: target-function,
        target-args: target-args,
        has-metadata: has-meta
      })
    
    ;; Store metadata if provided
    (if has-meta
      (map-set proposal-metadata
        proposal-id
        {
          details-uri: details-uri,
          additional-info: additional-info
        })
      true)
    
    (ok proposal-id))
)

;; Vote on a proposal
(define-public (vote-on-proposal (proposal-id uint) (vote-type uint))
  (let ((caller tx-sender)
        (effective-voter (get-effective-voter caller)))
    
    ;; Validate input and permissions
    (asserts! (var-get dao-initialized) ERR-DAO-NOT-INITIALIZED)
    (asserts! (proposal-exists proposal-id) ERR-PROPOSAL-NOT-FOUND)
    (asserts! (is-proposal-active proposal-id) ERR-PROPOSAL-NOT-ACTIVE)
    (asserts! (not (has-voting-ended proposal-id)) ERR-VOTING-PERIOD-ENDED)
    (asserts! (can-vote caller) ERR-NOT-AUTHORIZED)
    (asserts! (is-none (map-get? votes { proposal-id: proposal-id, voter: effective-voter })) ERR-ALREADY-VOTED)
    (asserts! (or (is-eq vote-type VOTE-FOR) (is-eq vote-type VOTE-AGAINST) (is-eq vote-type VOTE-ABSTAIN)) ERR-INVALID-PARAMETER)
    
    ;; Determine voting power
    (let ((power (get-voting-power effective-voter)))
      ;; Record the vote
      (map-set votes
        { proposal-id: proposal-id, voter: effective-voter }
        { vote-type: vote-type, weight: power, voted-at-block: block-height })
      
      ;; Update vote tallies in the proposal
      (match (map-get? proposals proposal-id)
        proposal (map-set proposals
                   proposal-id
                   (merge proposal 
                     (if (is-eq vote-type VOTE-FOR)
                       { yes-votes: (+ (get yes-votes proposal) power) }
                       (if (is-eq vote-type VOTE-AGAINST)
                         { no-votes: (+ (get no-votes proposal) power) }
                         { abstain-votes: (+ (get abstain-votes proposal) power) }))))
        (err ERR-PROPOSAL-NOT-FOUND))
      
      (ok true)))
)

;; Finalize a proposal after voting period ends
(define-public (finalize-proposal (proposal-id uint))
  (let ((caller tx-sender))
    ;; Validate proposal state
    (asserts! (var-get dao-initialized) ERR-DAO-NOT-INITIALIZED)
    (asserts! (proposal-exists proposal-id) ERR-PROPOSAL-NOT-FOUND)
    (asserts! (is-proposal-active proposal-id) ERR-PROPOSAL-NOT-ACTIVE)
    (asserts! (has-voting-ended proposal-id) ERR-VOTING-PERIOD-NOT-ENDED)
    
    ;; Update status based on voting outcome
    (if (has-proposal-passed proposal-id)
      (update-proposal-status proposal-id STATUS-PASSED)
      (if (has-met-quorum proposal-id)
        (update-proposal-status proposal-id STATUS-REJECTED)
        (update-proposal-status proposal-id STATUS-EXPIRED)))
    
    (ok true))
)

;; Execute an approved proposal
(define-public (execute-proposal (proposal-id uint))
  (let ((caller tx-sender))
    ;; Validate proposal state
    (asserts! (var-get dao-initialized) ERR-DAO-NOT-INITIALIZED)
    (asserts! (is-admin caller) ERR-NOT-AUTHORIZED)
    (asserts! (proposal-exists proposal-id) ERR-PROPOSAL-NOT-FOUND)
    
    (match (map-get? proposals proposal-id)
      proposal (begin
        ;; Check if the proposal is in the correct state
        (asserts! (is-eq (get status proposal) STATUS-PASSED) ERR-PROPOSAL-NOT-ACTIVE)
        (asserts! (is-none (get executed-at-block proposal)) ERR-PROPOSAL-ALREADY-EXECUTED)
        
        ;; Check if we need to create a timelock for this operation
        (match (get target-contract proposal)
          contract (match (get target-function proposal)
                     function (match (get target-args proposal)
                                args (begin
                                  ;; Record execution
                                  (record-proposal-execution proposal-id)
                                  
                                  ;; In a real implementation, we would execute the proposal action here
                                  ;; by calling the target contract/function with the provided args
                                  ;; This is a simplified version focusing on the core logic
                                  
                                  (ok true))
                                ERR-INVALID-PARAMETER)
                     ERR-INVALID-PARAMETER)
          ;; No target contract/function means this was just a governance proposal
          (begin
            (record-proposal-execution proposal-id)
            (ok true)))
      )
      ERR-PROPOSAL-NOT-FOUND)
  )
)

;; Create a timelock operation for high-value transfers
(define-public (create-timelock-operation 
  (proposal-id uint)
  (target-contract principal)
  (target-function (string-ascii 128))
  (target-args (list 20 (string-utf8 500))))
  (let ((caller tx-
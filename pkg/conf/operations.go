package conf

const (
	// OperationOperator - Initiator acts as operator, managing the peer
	OperationOperator = "operator"
	// OperationGateway - Initiator acts as relay user, traversing the peer
	OperationGateway = "gateway"
	// OperationAgent - Initiator acts as agent, requesting control from the peer (callback)
	OperationAgent = "agent"
	// OperationCallback - Gateway initiates connection but requests to BE controlled by the peer
	OperationCallback = "callback"
)

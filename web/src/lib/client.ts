import { createClient } from "@connectrpc/connect";
import { createGrpcWebTransport } from "@connectrpc/connect-web";
import { LanpilotService } from "../gen/lanpilot/v1/lanpilot_pb";

// gRPC-Web transport communicates directly over HTTP using the gRPC-Web protocol
const transport = createGrpcWebTransport({
  baseUrl: window.location.origin,
});

export const rpcClient = createClient(LanpilotService, transport);

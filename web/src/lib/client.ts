import { createClient } from "@connectrpc/connect";
import { createGrpcWebTransport } from "@connectrpc/connect-web";
import { RouterMonitorService } from "../gen/routermonitor/v1/router_monitor_pb";

// gRPC-Web transport communicates directly over HTTP using the gRPC-Web protocol
const transport = createGrpcWebTransport({
  baseUrl: window.location.origin,
});

export const rpcClient = createClient(RouterMonitorService, transport);

#include <iostream>
#include <grpc++/grpc++.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>
#include "fastrg_node_grpc.h"
#include "../../src/fastrg.h"

#ifdef __cplusplus
extern "C" {
#endif

void *fastrg_grpc_server_run(void *arg) {
    FastRG_t *fastrg_ccb = (FastRG_t *)arg;

    std::string unix_sock_path(fastrg_ccb->unix_sock_path);
    std::string ip_address(fastrg_ccb->node_grpc_ip_port);
    std::cout << "grpc server starting..." << std::endl;
    grpc::ServerBuilder builder;

    grpc::EnableDefaultHealthCheckService(true);
    std::shared_ptr<grpc::ServerCredentials> cred = grpc::InsecureServerCredentials();
    builder.AddListeningPort(unix_sock_path, cred);
    builder.AddListeningPort(ip_address, cred);
    FastRGNodeServiceImpl fastrg_service(fastrg_ccb);
    builder.RegisterService(&fastrg_service);

    std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
    std::cout << "grpc server listening on " << unix_sock_path << " and " << ip_address << std::endl;
    server->Wait();
    
    pthread_exit(NULL);
}

#ifdef __cplusplus
}
#endif

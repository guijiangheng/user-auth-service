package main

import (
	"log"
	"net"
	"user-auth-service/internal/auth"
	"user-auth-service/internal/db"
	"user-auth-service/internal/middleware"
	authv1 "user-auth-service/pkg/api/auth/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

const (
	grpcPort    = ":50051"
	postgresDSN = "host=localhost user=postgres password=postgres dbname=authdb port=5432 sslmode=disable"
)

func main() {
	userRepo, err := db.NewUserRepo(postgresDSN)
	if err != nil {
		log.Fatalf("Failed to connect to postgres: %v. Please ensure Postgres is running", err)
	}

	sessionManager := auth.NewSessionManager(userRepo)

	authServer := &auth.AuthServiceServer{
		UserRepo:       userRepo,
		SessionManager: sessionManager,
	}

	interceptor := middleware.SessionAuthInterceptor(sessionManager)
	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(interceptor),
	)

	authv1.RegisterAuthServiceServer(grpcServer, authServer)

	reflection.Register(grpcServer)
	log.Println("gRPC Server Reflection enabled on port 50051.")

	lis, err := net.Listen("tcp", grpcPort)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	log.Printf("Server listening on %s", grpcPort)

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}

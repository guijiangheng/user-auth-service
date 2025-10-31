package auth

import (
	"context"
	"strconv"
	"strings"

	"user-auth-service/internal/db"
	authv1 "user-auth-service/pkg/api/auth/v1"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type AuthServiceServer struct {
	authv1.UnimplementedAuthServiceServer
	UserRepo       *db.UserRepo
	SessionManager *SessionManager
}

func (s *AuthServiceServer) Register(ctx context.Context, req *authv1.RegisterRequest) (*authv1.RegisterResponse, error) {
	if req.Username == "" || req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "username and password are required")
	}

	userId, err := s.UserRepo.CreateUser(req.Username, req.Password)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			return nil, status.Error(codes.AlreadyExists, "username already exists")
		}
		return nil, status.Error(codes.Internal, "failed to register user")
	}

	return &authv1.RegisterResponse{UserId: strconv.FormatInt(userId, 10)}, nil
}

func (s *AuthServiceServer) Login(ctx context.Context, req *authv1.LoginRequest) (*authv1.LoginResponse, error) {
	userId, passwordHash, err := s.UserRepo.GetPasswordHashByUsername(req.Username)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid username or password")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)); err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid username or password")
	}

	sessionId, err := s.SessionManager.CreateSession(userId)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to create session")
	}

	grpc.SetHeader(ctx, metadata.Pairs("session-id", sessionId))

	userIdStr := strconv.FormatInt(userId, 10)
	return &authv1.LoginResponse{UserId: userIdStr}, nil
}

func (s *AuthServiceServer) GetUserInfo(ctx context.Context, req *authv1.GetUserInfoRequest) (*authv1.GetUserInfoResponse, error) {
	userId, ok := ctx.Value("userId").(string)
	if !ok || userId == "" {
		return nil, status.Error(codes.Unauthenticated, "user not authenticated")
	}

	return &authv1.GetUserInfoResponse{
		UserId:   userId,
		Username: "User_" + userId,
	}, nil
}

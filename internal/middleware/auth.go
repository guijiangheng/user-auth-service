package middleware

import (
	"context"
	"strconv"
	"strings"
	"user-auth-service/internal/auth"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func SessionAuthInterceptor(m *auth.SessionManager) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		if isPublicMethod(info.FullMethod) {
			return handler(ctx, req)
		}

		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}

		sessionIds := md["session-id"]
		if len(sessionIds) == 0 {
			return nil, status.Error(codes.Unauthenticated, "missing session id header")
		}

		sessionId := sessionIds[0]

		userId, err := m.GetUserIdBySessionId(ctx, sessionId)
		if err != nil {
			return nil, status.Error(codes.Internal, "session verification failed")
		}

		if userId == 0 {
			return nil, status.Error(codes.Unauthenticated, "invalid or expired session")
		}

		ctx = context.WithValue(ctx, "userId", strconv.FormatInt(userId, 10))
		return handler(ctx, req)
	}
}

func isPublicMethod(fullMethod string) bool {
	publicMethods := map[string]bool{
		"/auth.v1.AuthService/Register": true,
		"/auth.v1.AuthService/Login":    true,
	}

	if strings.Contains(fullMethod, "ServerReflection") {
		return true
	}

	return publicMethods[fullMethod]
}

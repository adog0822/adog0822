/**
 * Auth Middleware
 *
 * Express-style middleware for authentication and authorization.
 * Supports:
 * - Standard session tokens for workspace members
 * - Time-bound auditor sessions with scope limits
 * - Guest access with restricted permissions
 *
 * Extracts user and workspace context from the session token
 * and attaches it to the request for downstream handlers.
 */

import type {
  AuditorScope,
  SessionToken,
  User,
  UserRole,
  Workspace,
  UUID,
} from '../../types';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AuthRequest {
  headers: Record<string, string | string[] | undefined>;
  /** Populated by this middleware */
  user?: User;
  workspace?: Workspace;
  session?: SessionToken;
}

export interface AuthResponse {
  status: (code: number) => AuthResponse;
  json: (body: unknown) => void;
}

export type AuthNextFunction = () => void;

export interface AuthMiddlewareOptions {
  /** Roles that are allowed to access the route */
  allowedRoles?: UserRole[];
  /** Whether to allow guest (unauthenticated) access */
  allowGuest?: boolean;
  /** Whether this route requires an auditor session */
  requireAuditorSession?: boolean;
}

// ---------------------------------------------------------------------------
// Middleware Factory
// ---------------------------------------------------------------------------

/**
 * Creates auth middleware with the specified options.
 *
 * Usage:
 * ```typescript
 * // Require authentication, any role
 * app.use(createAuthMiddleware());
 *
 * // Restrict to admins and owners
 * app.use(createAuthMiddleware({ allowedRoles: ['admin', 'owner'] }));
 *
 * // Allow guest access
 * app.use(createAuthMiddleware({ allowGuest: true }));
 *
 * // Require auditor session
 * app.use(createAuthMiddleware({ requireAuditorSession: true }));
 * ```
 */
export function createAuthMiddleware(options: AuthMiddlewareOptions = {}) {
  const {
    allowedRoles,
    allowGuest = false,
    requireAuditorSession = false,
  } = options;

  return async function authMiddleware(
    req: AuthRequest,
    res: AuthResponse,
    next: AuthNextFunction
  ): Promise<void> {
    const authHeader = getAuthHeader(req);

    // Handle missing auth header
    if (!authHeader) {
      if (allowGuest) {
        attachGuestContext(req);
        next();
        return;
      }

      res.status(401).json({
        success: false,
        error: {
          code: 'UNAUTHORIZED',
          message: 'Authentication required. Provide a Bearer token in the Authorization header.',
        },
      });
      return;
    }

    // Validate the token
    const token = extractBearerToken(authHeader);
    if (!token) {
      res.status(401).json({
        success: false,
        error: {
          code: 'INVALID_TOKEN_FORMAT',
          message: 'Invalid Authorization header format. Expected: Bearer <token>.',
        },
      });
      return;
    }

    let sessionToken: SessionToken;
    try {
      sessionToken = await verifyToken(token);
    } catch {
      res.status(401).json({
        success: false,
        error: {
          code: 'INVALID_TOKEN',
          message: 'Session token is invalid or has been revoked.',
        },
      });
      return;
    }

    // Check token expiration
    if (isTokenExpired(sessionToken)) {
      res.status(401).json({
        success: false,
        error: {
          code: 'TOKEN_EXPIRED',
          message: 'Session has expired. Please sign in again.',
        },
      });
      return;
    }

    // For auditor sessions, check the auditor-specific expiry
    if (sessionToken.auditorScope && sessionToken.expiresAt) {
      if (new Date(sessionToken.expiresAt) < new Date()) {
        res.status(401).json({
          success: false,
          error: {
            code: 'AUDITOR_SESSION_EXPIRED',
            message: 'Your auditor session has expired. Contact the workspace administrator for a new session.',
          },
        });
        return;
      }
    }

    // Require auditor session if specified
    if (requireAuditorSession && !sessionToken.auditorScope) {
      res.status(403).json({
        success: false,
        error: {
          code: 'AUDITOR_SESSION_REQUIRED',
          message: 'This endpoint requires an active auditor session.',
        },
      });
      return;
    }

    // Check role permissions
    if (allowedRoles && !allowedRoles.includes(sessionToken.role)) {
      res.status(403).json({
        success: false,
        error: {
          code: 'FORBIDDEN',
          message: `Insufficient permissions. Required roles: ${allowedRoles.join(', ')}.`,
        },
      });
      return;
    }

    // Load user and workspace
    const user = await loadUser(sessionToken.userId);
    if (!user) {
      res.status(401).json({
        success: false,
        error: {
          code: 'USER_NOT_FOUND',
          message: 'User associated with this token no longer exists.',
        },
      });
      return;
    }

    const workspace = await loadWorkspace(sessionToken.workspaceId);
    if (!workspace) {
      res.status(401).json({
        success: false,
        error: {
          code: 'WORKSPACE_NOT_FOUND',
          message: 'Workspace associated with this token no longer exists.',
        },
      });
      return;
    }

    // Attach context to request
    req.user = user;
    req.workspace = workspace;
    req.session = sessionToken;

    next();
  };
}

// ---------------------------------------------------------------------------
// Convenience Middleware Factories
// ---------------------------------------------------------------------------

/**
 * Middleware requiring admin or owner role.
 */
export function requireAdmin() {
  return createAuthMiddleware({ allowedRoles: ['admin', 'owner'] });
}

/**
 * Middleware requiring an active auditor session.
 */
export function requireAuditor() {
  return createAuthMiddleware({
    allowedRoles: ['auditor'],
    requireAuditorSession: true,
  });
}

/**
 * Middleware allowing guest access with limited permissions.
 */
export function allowGuest() {
  return createAuthMiddleware({ allowGuest: true });
}

/**
 * Middleware requiring at least member-level access.
 */
export function requireMember() {
  return createAuthMiddleware({ allowedRoles: ['member', 'admin', 'owner'] });
}

// ---------------------------------------------------------------------------
// Token Utilities
// ---------------------------------------------------------------------------

/**
 * Extracts the Authorization header value from the request.
 * @internal
 */
function getAuthHeader(req: AuthRequest): string | null {
  const header = req.headers['authorization'] ?? req.headers['Authorization'];
  if (!header) return null;
  return Array.isArray(header) ? header[0] : header;
}

/**
 * Extracts the Bearer token from an Authorization header value.
 * @internal
 */
function extractBearerToken(header: string): string | null {
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match ? match[1] : null;
}

/**
 * Checks whether a token has expired based on its `exp` claim.
 * @internal
 */
function isTokenExpired(token: SessionToken): boolean {
  const nowSeconds = Math.floor(Date.now() / 1000);
  return token.exp < nowSeconds;
}

/**
 * Attaches a guest context to the request.
 * Guest users have read-only access to public resources.
 * @internal
 */
function attachGuestContext(req: AuthRequest): void {
  req.session = {
    userId: 'guest',
    workspaceId: '',
    role: 'guest',
    isGuest: true,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
  };
}

// ---------------------------------------------------------------------------
// Persistence Stubs
// ---------------------------------------------------------------------------

/**
 * Verifies and decodes a session token.
 * In production this would verify a JWT signature or look up an opaque token.
 * @internal
 */
async function verifyToken(token: string): Promise<SessionToken> {
  // TODO: Implement JWT verification or session store lookup
  void token;
  return {
    userId: '',
    workspaceId: '',
    role: 'member',
    isGuest: false,
    iat: 0,
    exp: 0,
  };
}

/** @internal */
async function loadUser(userId: UUID): Promise<User | null> {
  void userId;
  return null;
}

/** @internal */
async function loadWorkspace(workspaceId: UUID): Promise<Workspace | null> {
  void workspaceId;
  return null;
}

// ---------------------------------------------------------------------------
// Scope Checking Utilities (exported for use in route handlers)
// ---------------------------------------------------------------------------

/**
 * Checks whether a control ID is within an auditor's scope.
 */
export function isControlInScope(controlId: UUID, scope: AuditorScope): boolean {
  return scope.controlIds.includes(controlId);
}

/**
 * Checks whether a category is within an auditor's scope.
 */
export function isCategoryInScope(
  category: string,
  scope: AuditorScope
): boolean {
  return scope.categories.includes(category as AuditorScope['categories'][number]);
}

{-# LANGUAGE PolyKinds #-}
{-# LANGUAGE UndecidableInstances #-}
module Servant.Auth.Server.Internal.Class where

import Servant.Auth
import Data.Monoid
import Servant hiding (BasicAuth)

import Servant.Auth.Server.Internal.Types
import Servant.Auth.Server.Internal.ConfigTypes
import Servant.Auth.Server.Internal.BasicAuth
import Servant.Auth.Server.Internal.Cookie
import Servant.Auth.Server.Internal.JWT

------------------------------------------------------------------------------
-- Type families of functions
------------------------------------------------------------------------------

-- | This type family represents (or builds) the type of a function with
-- argument types in the 'args' list in that order and returning a result of
-- type 'res'.
type family FnRep args res where
    FnRep '[] res = res
    FnRep (arg1 ': rest) res = arg1 -> FnRep rest res

-- | This type family proves that the function type 'fn' can be applied to the
-- argument types in 'args' one at a time, and represents the final result of
-- the application.
type family FnApp fn args where
    FnApp res '[] = res
    FnApp (arg1 -> res) (arg1 ': rest) = FnApp res rest

------------------------------------------------------------------------------
-- Implement a particular type of auth
------------------------------------------------------------------------------

-- mkAuth does not do anything, it just wraps the auth function in a type
-- family.
class IsAuth auth (tag :: k) result where
    type AuthCtxArgs auth :: [*]
    mkAuth
        :: proxy auth
        -> proxy1 tag
        -> proxy result
        -> FnRep (AuthCtxArgs auth) (AuthCheck result)

class DemoteKind (a :: k) where
    demoteKind :: proxy a -> k

-- | Demote a type level (compile time) list of types to a term level (runtime)
-- list of values

instance DemoteKind '[] where
    demoteKind _ = []

instance (DemoteKind x, DemoteKind xs) => DemoteKind (x ': xs) where
    demoteKind _ = demoteKind (Proxy :: Proxy x)
        : demoteKind (Proxy :: Proxy xs)

instance {-# OVERLAPPING  #-} (FromJWT usr) => IsAuth JWT '() usr where
    type AuthCtxArgs JWT = '[JWTSettings]
    mkAuth _ _ _ = jwtAuthCheck

instance {-# OVERLAPPING  #-} (FromJWT usr) => IsAuth Cookie '() usr where
    type AuthCtxArgs Cookie = '[ CookieSettings, JWTSettings]
    mkAuth _ _ _ = cookieAuthCheck

instance {-# OVERLAPPING  #-} (FromBasicAuthData usr) => IsAuth BasicAuth '() usr where
    type AuthCtxArgs BasicAuth = '[BasicAuthCfg]
    mkAuth _ _ _ = basicAuthCheck

instance (DemoteKind tag, FromJWTTagged usr) => IsAuth Cookie tag usr where
    type AuthCtxArgs Cookie = '[ CookieSettings, JWTSettings]
    mkAuth _ _ _ = cookieAuthCheckTagged (demoteKind (Proxy :: Proxy tag))

instance (DemoteKind tag, FromJWTTagged usr) => IsAuth JWT tag usr where
    type AuthCtxArgs JWT = '[JWTSettings]
    mkAuth _ _ _ = jwtAuthCheckTagged (demoteKind (Proxy :: Proxy tag))

instance (DemoteKind tag, FromBasicAuthDataTagged usr)
    => IsAuth BasicAuth tag usr where
    type AuthCtxArgs BasicAuth = '[BasicAuthCfg]
    mkAuth _ _ _ = basicAuthCheckTagged (demoteKind (Proxy :: Proxy tag))

------------------------------------------------------------------------------
-- Apply a function from a list of functions with context and other attributes,
-- privileges derived from the type.
------------------------------------------------------------------------------

-- | @appWithCtx@ picks an argument _type_ from @args@ and fetches the
-- corresponding value from the conexts provided in the first argument and
-- applies @fn@ to it, the result of the aplication is successively applied to
-- other arguments until the arguments are exhausted.
class AppWithCtx ts fn args where
    appWithCtx :: Context ts -> fn -> proxy args -> FnApp fn args

instance AppWithCtx ts fn '[] where
  appWithCtx _ fn _ = fn

instance (HasContextEntry ts ctx, AppWithCtx ts res args)
    => AppWithCtx ts (ctx -> res) (ctx ': args) where
    appWithCtx allCtxs fn _ =
        appWithCtx allCtxs (fn $ getContextEntry allCtxs) (Proxy :: Proxy args)

------------------------------------------------------------------------------
-- Combine all auth types in a list of auths
------------------------------------------------------------------------------

class IsAuthList (auths :: [*]) (ts :: [*]) (tag :: k) res where
    runAuthList :: proxy auths -> proxy1 tag -> Context ts -> AuthCheck res

type AreAuths (auths :: [*]) (ts :: [*]) res
    = (IsAuthList (auths :: [*]) (ts :: [*]) '() res)

instance IsAuthList '[] ts tag res where
    runAuthList _ _ _ = mempty

instance ( IsAuth a tag res
         , IsAuthList as ts tag res
         , AuthCheck res ~
           FnApp (FnRep (AuthCtxArgs a) (AuthCheck res)) (AuthCtxArgs a)
         , AppWithCtx ts (FnRep (AuthCtxArgs a) (AuthCheck res)) (AuthCtxArgs a)
         ) => IsAuthList (a ': as) ts tag res
    where
    runAuthList _ _ allCtxs =
        go <> runAuthList (Proxy :: Proxy as) (Proxy :: Proxy tag) allCtxs
        where
        go = appWithCtx
                allCtxs
                (mkAuth (Proxy :: Proxy a)
                        (Proxy :: Proxy tag)
                        (Proxy :: Proxy res))
                (Proxy :: Proxy (AuthCtxArgs a))

{-# LANGUAGE UndecidableInstances #-}
module Servant.Auth.Server.Internal.Class where

import Servant.Auth
import Data.Monoid
import Servant hiding (BasicAuth)

import Servant.Auth.Server.Internal.Types
import Servant.Auth.Server.Internal.ConfigTypes
import Servant.Auth.Server.Internal.RoleTypes
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
class IsAuth auth (attrs :: [RoleAttribute]) (privs :: [RolePriv]) result where
    type AuthCtxArgs auth :: [*]
    mkAuth
        :: proxy auth
        -> proxy1 attrs
        -> proxy2 privs
        -> proxy result
        -> FnRep (AuthCtxArgs auth) (AuthCheck result)

instance (DemoteAttrList attrs, DemotePrivList privs, FromJWT usr)
    => IsAuth Cookie attrs privs usr where
    type AuthCtxArgs Cookie = '[ CookieSettings, JWTSettings]
    mkAuth _ _ _ _ =
        cookieAuthCheck (demoteAttrList (Proxy :: Proxy attrs))
                        (demotePrivList (Proxy :: Proxy privs))

instance (DemoteAttrList attrs, DemotePrivList privs, FromJWT usr)
    => IsAuth JWT attrs privs usr where
    type AuthCtxArgs JWT = '[JWTSettings]
    mkAuth _ _ _ _ =
        jwtAuthCheck (demoteAttrList (Proxy :: Proxy attrs))
                     (demotePrivList (Proxy :: Proxy privs))

instance (DemoteAttrList attrs, DemotePrivList privs, FromBasicAuthData usr)
    => IsAuth BasicAuth attrs privs usr where
    type AuthCtxArgs BasicAuth = '[BasicAuthCfg]
    mkAuth _ _ _ _ =
        basicAuthCheck (demoteAttrList (Proxy :: Proxy attrs))
                       (demotePrivList (Proxy :: Proxy privs))

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

class IsAuthList (auths :: [*])
               (attrs :: [RoleAttribute])
               (privs :: [RolePriv])
               (ts :: [*]) -- contexts type level list
               res
    where
    runAuthList :: proxy auths -> proxy1 attrs -> proxy2 privs -> Context ts
             -> AuthCheck res

instance  IsAuthList '[] attrs privs ts res where
    runAuthList _ _ _ _ = mempty

instance ( IsAuth a attrs privs res
         , IsAuthList as attrs privs ts res
         , AuthCheck res ~
           FnApp (FnRep (AuthCtxArgs a) (AuthCheck res)) (AuthCtxArgs a)
         , AppWithCtx ts (FnRep (AuthCtxArgs a) (AuthCheck res)) (AuthCtxArgs a)
         ) => IsAuthList (a ': as) attrs privs ts res
    where
    runAuthList _ _ _ allCtxs =
        go <> runAuthList (Proxy :: Proxy as)
                          (Proxy :: Proxy attrs)
                          (Proxy :: Proxy privs)
                          allCtxs
        where
        go = appWithCtx
                allCtxs
                (mkAuth (Proxy :: Proxy a)
                         (Proxy :: Proxy attrs)
                         (Proxy :: Proxy privs)
                         (Proxy :: Proxy res))
                (Proxy :: Proxy (AuthCtxArgs a))

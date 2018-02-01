module Servant.Auth.Server.Internal.RoleTypes
where

import Data.Proxy (Proxy(..))
import GHC.Generics (Generic)

-- | Attributes for a role.
data RoleAttribute
    = SuperUser
    | UserAdmin
    | RoleAdmin
    | Inherit
    | Enabled -- XXX we can use empty privilege instead?
    | Public
    deriving (Generic, Show)

-- | Privileges for a role.
data RolePriv
    = PrivCreate
    | PrivRead
    | PrivUpdate
    | PrivDelete
    deriving (Generic, Show)

-- | Convert a promoted type of RoleAttribute kind back to the term level
-- constructor
class DemoteAttr (a :: RoleAttribute) where
    demoteAttr ::  proxy a -> RoleAttribute

instance DemoteAttr SuperUser where
    demoteAttr _ = SuperUser

instance DemoteAttr UserAdmin where
    demoteAttr _ = UserAdmin

instance DemoteAttr RoleAdmin where
    demoteAttr _ = RoleAdmin

instance DemoteAttr Inherit where
    demoteAttr _ = Inherit

instance DemoteAttr Enabled where
    demoteAttr _ = Enabled

instance DemoteAttr Public where
    demoteAttr _ = Public

class DemotePriv (a :: RolePriv) where
    demotePriv ::  proxy a -> RolePriv

instance DemotePriv PrivCreate where
    demotePriv _ = PrivCreate

instance DemotePriv PrivRead where
    demotePriv _ = PrivRead

instance DemotePriv PrivUpdate where
    demotePriv _ = PrivUpdate

instance DemotePriv PrivDelete where
    demotePriv _ = PrivDelete

-- | Convert a type level list of Symbols to a term level list of strings
-- Demote a type level (compile time) list of types to a term level (runtime)
-- list of values
class DemoteAttrList (a :: [RoleAttribute]) where
    demoteAttrList :: proxy a -> [RoleAttribute]

instance DemoteAttrList '[] where
    demoteAttrList _ = []

instance (DemoteAttr x, DemoteAttrList xs) => DemoteAttrList (x ': xs) where
    demoteAttrList _ = demoteAttr (Proxy :: Proxy x)
        : demoteAttrList (Proxy :: Proxy xs)

class DemotePrivList (a :: [RolePriv]) where
    demotePrivList :: proxy a -> [RolePriv]

instance DemotePrivList '[] where
    demotePrivList _ = []

instance (DemotePriv x, DemotePrivList xs) => DemotePrivList (x ': xs) where
    demotePrivList _ = demotePriv (Proxy :: Proxy x)
        : demotePrivList (Proxy :: Proxy xs)

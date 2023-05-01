{-# LANGUAGE FlexibleInstances #-}

module Data.HaSec
  ( Vulnerability (..),
    vulnerabilityCodec,
    Advisory (..),
    AdvisoryId (..),
    AdvisoryUrl (..),
    CWE (..),
    CVSS (..),
    Affected (..),
    Versions (..),
    PackageName (..),
    Version (..),
    VersionSpec (..),
    VulnerableVersionSpec (..),
    ActualVersionSpec (..),
    isVulnerableVersion,
    parseVersionSpec,
    parseVersion,
  )
where

import Control.Monad (guard)
import Data.Function (on)
import Data.Functor
import Data.Functor.Classes
import Data.List (intercalate)
import qualified Data.List.NonEmpty as NonEmpty
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time
import GHC.Exts
import GHC.Generics
import Text.Parsec
import qualified Text.Parsec.Expr as Expr
import qualified Toml

data Vulnerability = Vulnerability
  { advisory :: Advisory,
    affected :: Affected,
    versions :: Versions
  }
  deriving stock (Eq, Show, Generic)

vulnerabilityCodec :: Toml.TomlCodec Vulnerability
vulnerabilityCodec = Toml.genericCodec

data Advisory = Advisory
  { id :: AdvisoryId, -- HSEC-YYYY-NNNN
    package :: PackageName,
    date :: Day,
    url :: Maybe AdvisoryUrl,
    cwe :: [CWE], -- int
    cvss :: CVSS, -- text
    aliases :: [Text],
    related :: [Text]
  }
  deriving stock (Eq, Show, Generic)

instance Toml.HasCodec Advisory where
  hasCodec = Toml.table Toml.genericCodec

data AdvisoryId = AdvisoryId
  { advisoryIdYear :: Int,
    advisoryIdNumber :: Int
  }
  deriving stock (Eq, Ord, Generic)

instance Show AdvisoryId where
  show x = "HSEC-" <> show x.advisoryIdYear <> T.unpack (T.justifyRight 4 '0' $ T.pack $ show x.advisoryIdNumber)

instance Toml.HasCodec AdvisoryId where
  hasCodec = Toml.match $ Toml.mkAnyValueBiMap undefined undefined

newtype AdvisoryUrl = AdvisoryUrl {getAdvisoryUrl :: Text}
  deriving stock (Eq, Ord, Show, Generic)
  deriving newtype (Toml.HasCodec)

-- deriving newtype (FromJSON, ToJSON)

newtype CWE = CWE {getCWE :: Int}
  deriving stock (Eq, Ord, Show, Generic)
  deriving newtype (Toml.HasCodec, Toml.HasItemCodec)

newtype CVSS = CVSS {getCVSS :: Text}
  deriving stock (Eq, Ord, Show, Generic)
  deriving newtype (Toml.HasCodec)

-- deriving newtype (FromJSON, ToJSON)

data Affected = Affected
  { arch :: [Text],
    os :: [Text],
    declarations :: [(Text, VersionSpec)]
  }
  deriving stock (Eq, Show, Generic)

instance Toml.HasCodec Affected where
  hasCodec = Toml.table Toml.genericCodec

instance Toml.HasItemCodec (Text, VersionSpec) where
  hasItemCodec = error "TODO"

newtype Versions = Versions
  { affected :: VersionSpec
  }
  deriving stock (Eq, Show, Generic)

instance Toml.HasCodec Versions where
  hasCodec = Toml.table Toml.genericCodec

-- | Package name
newtype PackageName = PackageName {getPackageName :: Text}
  deriving stock (Eq, Ord, Show, Generic)
  deriving newtype (IsString, Toml.HasCodec)

-- | Final version
newtype Version = Version {getVersion :: NonEmpty.NonEmpty Int}
  deriving stock (Eq, Ord, Generic)

instance Show Version where
  show = intercalate "." . map show . NonEmpty.toList . getVersion

compareVersions :: Version -> Version -> Ordering
compareVersions = liftCompare compare `on` getVersion

-- | Specified version
data VersionSpec
  = VSEqual Version -- \* "=="
  | VSUpper Version -- \* ">"
  | VSLower Version -- \* "<"
  | VSMin Version -- \* ">="
  | VSMajor Version -- \* "^>="
  | VSMax Version -- \* "<="
  | VSAnd VersionSpec VersionSpec -- \* "&&"
  | VSOr VersionSpec VersionSpec -- \* "||"
  | VSAny -- \* Not specified or any/all
  deriving stock (Eq, Show, Generic)

instance Toml.HasCodec VersionSpec where
  hasCodec = error "TODO"

instance Toml.HasItemCodec VersionSpec where
  hasItemCodec = error "TODO"

newtype VulnerableVersionSpec = VulnerableVersionSpec {getVulnerableVersionSpec :: VersionSpec}
  deriving stock (Eq, Show, Generic)

newtype ActualVersionSpec = ActualVersionSpec {getActualVersionSpec :: VersionSpec}
  deriving stock (Eq, Show, Generic)

isVulnerableVersion :: VulnerableVersionSpec -> ActualVersionSpec -> Bool
isVulnerableVersion (VulnerableVersionSpec vulnerability) (ActualVersionSpec actual) =
  go (vulnerability, actual)
  where
    go :: (VersionSpec, VersionSpec) -> Bool
    go =
      \case
        (VSAny, _) -> True
        (_, VSAny) -> True
        (VSOr x y, o) -> go (x, o) || go (y, o)
        (o, VSOr x y) -> go (o, x) || go (o, y)
        (VSAnd x y, o) -> go (x, o) && go (y, o)
        (o, VSAnd x y) -> go (o, x) && go (o, y)
        (VSEqual x, VSEqual y) -> x == y
        (VSUpper x, VSEqual y) -> compareVersions x y == LT
        (VSLower x, VSEqual y) -> compareVersions x y == GT
        (VSEqual x, VSUpper y) -> compareVersions x y == GT
        (VSEqual x, VSLower y) -> compareVersions x y == LT
        (VSEqual x, VSMin y) -> compareVersions x y `elem` [EQ, GT]
        (VSEqual x, VSMax y) -> compareVersions x y `elem` [EQ, LT]
        (VSMin x, VSEqual y) -> compareVersions x y `elem` [EQ, LT]
        (VSMax x, VSEqual y) -> compareVersions x y `elem` [EQ, GT]
        (VSMajor x, y) -> go (canonicalizeMajor x, y)
        (x, VSMajor y) -> go (x, canonicalizeMajor y)
        (VSUpper _, VSMin _) -> True
        (VSUpper x, VSMax y) -> compareVersions x y == LT
        (VSUpper _, VSUpper _) -> True
        (VSUpper x, VSLower y) -> compareVersions x y == LT
        (VSLower x, VSMin y) -> compareVersions x y == GT
        (VSLower _, VSMax _) -> True
        (VSLower x, VSUpper y) -> compareVersions x y == GT
        (VSLower _, VSLower _) -> True
        (VSMin _, VSMin _) -> True
        (VSMin x, VSMax y) -> compareVersions x y == LT
        (VSMin _, VSUpper _) -> True
        (VSMin x, VSLower y) -> compareVersions x y == LT
        (VSMax x, VSMin y) -> compareVersions x y == GT
        (VSMax x, VSMax y) -> compareVersions x y == LT
        (VSMax x, VSUpper y) -> compareVersions x y == GT
        (VSMax _, VSLower _) -> True
    canonicalizeMajor :: Version -> VersionSpec
    canonicalizeMajor (Version xs) =
      let (y, ys) = NonEmpty.uncons xs
          y' = maybe 0 NonEmpty.head ys
          mkVersion v = Version $ y NonEmpty.<| NonEmpty.singleton v
       in VSMin (mkVersion y') `VSAnd` VSLower (mkVersion (y' + 1))

type Parser = Parsec Text ()

parseVersionSpec :: Text -> Either ParseError VersionSpec
parseVersionSpec = parse versionSpecP "parseVersionSpec"

versionSpecP :: Parser VersionSpec
versionSpecP = skipSpaces *> ((eof $> VSAny) <|> (goP <* eof))
  where
    goP :: Parser VersionSpec
    goP = Expr.buildExpressionParser table term
      where
        table = [[binary VSOr "||", binary VSAnd "&&"]]
          where
            binary func operator = Expr.Infix (func <$ symbol operator) Expr.AssocRight
        term =
          parens goP
            <|> try (unary VSEqual "==")
            <|> try (unary VSMin ">=")
            <|> try (unary VSMax "<=")
            <|> try (unary VSUpper ">")
            <|> try (unary VSLower "<")
            <|> try (unary VSMajor "^>=")
          where
            unary mkSpec op = mkSpec <$ symbol op <*> lexeme versionP
            parens = between (symbol "(") (symbol ")")

    skipSpaces = skipMany space
    lexeme :: Parser a -> Parser a
    lexeme p = p <* skipSpaces
    symbol name = lexeme (string name)

parseVersion :: Text -> Either ParseError Version
parseVersion = parse versionP "parseVersion"

versionP :: Parser Version
versionP = do
  let partP :: Parser Int
      partP = do
        xs <- many1 digit
        guard $
          case xs of
            ('0' : _ : _) -> False
            _ -> True
        return $ read xs
  Version . NonEmpty.fromList <$> sepBy1 partP (char '.')

module Main (main) where

import Control.Monad
import Data.Either (isLeft)
import Data.HaSec
import qualified Data.List.NonEmpty as NonEmpty
import qualified Data.Text as T
import Test.Hspec

main :: IO ()
main = hspec spec

spec :: Spec
spec = do
  describe "parseVersion" $ do
    describe "should be parsed" $ do
      forM_
        [ ("1", mkVersion "1"),
          ("0.0.5", mkVersion "0.0.5"),
          ("0.42", mkVersion "0.42"),
          ("25.0.0", mkVersion "25.0.0")
        ]
        $ \(raw, expected) ->
          it (T.unpack raw) $ parseVersion raw `shouldBe` Right expected
    describe "should not be parsed" $ do
      forM_ [".0", "01", "01.1", "1.02", "1.2.00", "1.2.03"] $ \raw ->
        it (T.unpack raw) $ parseVersion raw `shouldSatisfy` isLeft
  describe "parseVersionSpec" $ do
    describe "should be parsed" $ do
      forM_
        [ ("", VSAny),
          ("== 1", VSEqual $ mkVersion "1"),
          (">0.0.5", VSUpper $ mkVersion "0.0.5"),
          ("< 0.42", VSLower $ mkVersion "0.42"),
          (">=  25.0.0", VSMin $ mkVersion "25.0.0"),
          ("<= 25", VSMax $ mkVersion "25"),
          ("^>= 1.2.3.4", VSMajor $ mkVersion "1.2.3.4"),
          ("==1||==2", VSOr (VSEqual $ mkVersion "1") (VSEqual $ mkVersion "2")),
          (">1  &&  <2", VSAnd (VSUpper $ mkVersion "1") (VSLower $ mkVersion "2")),
          ("==1 && == 2 || ==3", (VSEqual $ mkVersion "1") `VSAnd` VSOr (VSEqual $ mkVersion "2") (VSEqual $ mkVersion "3")),
          ("((==1 && == 2)) || ==3", VSAnd (VSEqual $ mkVersion "1") (VSEqual $ mkVersion "2") `VSOr` (VSEqual $ mkVersion "3")),
          ("((==1 || == 2)) && ==3", VSOr (VSEqual $ mkVersion "1") (VSEqual $ mkVersion "2") `VSAnd` (VSEqual $ mkVersion "3"))
        ]
        $ \(raw, expected) ->
          it (T.unpack raw) $ parseVersionSpec raw `shouldBe` Right expected
  describe "isVulnerableVersion" $ do
    describe "is vulnerable" $ do
      forM_
        [ ("", ""),
          ("", "==1"),
          ("==1.1", "<=2"),
          ("==1.1", ">1"),
          ("==1", "==1"),
          ("==2||==1", "==1"),
          ("==1.1", "<=2&&>1"),
          (">=1", "==2"),
          (">=1", "==1"),
          ("==2", ">=2"),
          ("==2", ">1"),
          (">5", ">=2"),
          ("==5", ">=2"),
          ("==5", ">2"),
          (">=5", ">2"),
          ("<=5", ">2"),
          ("<5", ">=2"),
          (">=2", "==5"),
          (">2", "==5"),
          (">5", ">=5"),
          ("^>=1.1", ">1"),
          ("^>=1.1", "<2"),
          ("^>=1.1", "<=1.2"),
          ("^>=1.1", ">1.1"),
          ("^>=1.1", ">=1.1.5"),
          ("^>=1.1", ">=1")
        ]
        $ \(vuln, actual) -> do
          it ("vuln: " <> show vuln <> " with actual:" <> show actual) $ do
            -- print (VulnerableVersionSpec <$> parseVersionSpec vuln)
            -- print (ActualVersionSpec <$> parseVersionSpec actual)
            isVulnerableVersion
              <$> (VulnerableVersionSpec <$> parseVersionSpec vuln)
              <*> (ActualVersionSpec <$> parseVersionSpec actual)
              `shouldBe` Right True
          it ("vuln: " <> show actual <> " with actual:" <> show vuln) $ do
            -- print (VulnerableVersionSpec <$> parseVersionSpec actual)
            -- print (ActualVersionSpec <$> parseVersionSpec vuln)
            isVulnerableVersion
              <$> (VulnerableVersionSpec <$> parseVersionSpec actual)
              <*> (ActualVersionSpec <$> parseVersionSpec vuln)
              `shouldBe` Right True
    describe "is not vulnerable" $ do
      forM_
        [ ("==2.1", "<=2"),
          ("==1", ">1.1"),
          ("==2", "==1"),
          ("==2||==1", ">3"),
          ("==3", "<=2&&>1"),
          (">=2", "==1.1"),
          (">=1.1", "==1"),
          ("==2", ">=2.1"),
          ("==1", ">1"),
          ("<2", ">=2"),
          ("==2", ">=5"),
          ("==2", ">5"),
          ("<=2", ">5"),
          ("<=2", ">5"),
          ("<2", ">=5"),
          (">=2", "==1.1"),
          ("<2", "==5"),
          ("<5", ">=5"),
          ("^>=1.1", "<1"),
          ("^>=1.1", "<1.1"),
          ("^>=1.1", ">=1.2"),
          ("^>=1.1", "<=1"),
          ("^>=1.1", ">2"),
          ("^>=1.1", ">=2")
        ]
        $ \(vuln, actual) -> do
          it ("vuln: " <> show vuln <> " with actual:" <> show actual) $ do
            -- print (VulnerableVersionSpec <$> parseVersionSpec vuln)
            -- print (ActualVersionSpec <$> parseVersionSpec actual)
            isVulnerableVersion
              <$> (VulnerableVersionSpec <$> parseVersionSpec vuln)
              <*> (ActualVersionSpec <$> parseVersionSpec actual)
              `shouldBe` Right False
          it ("vuln: " <> show actual <> " with actual:" <> show vuln) $ do
            -- print (VulnerableVersionSpec <$> parseVersionSpec actual)
            -- print (ActualVersionSpec <$> parseVersionSpec vuln)
            isVulnerableVersion
              <$> (VulnerableVersionSpec <$> parseVersionSpec actual)
              <*> (ActualVersionSpec <$> parseVersionSpec vuln)
              `shouldBe` Right False

mkVersion :: T.Text -> Version
mkVersion = Version . NonEmpty.fromList . map (read . T.unpack) . T.splitOn "."

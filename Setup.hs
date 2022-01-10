{-# LANGUAGE LambdaCase #-}
module Main where

import Control.Monad
import Distribution.Simple
import Distribution.System (OS(..), buildOS)
import Debug.Trace
import Distribution.Types.LocalBuildInfo
import System.Process (system)
import System.Directory

main = defaultMainWithHooks $
  simpleUserHooks
    { postConf = \ _args _configFlags _packageDescription localBuildInfo -> do
        case buildOS of
          Windows -> error "Build is not supported on Windows yet."
          _ -> do
            let sourcePath = "cbits/libsodium-stable/src/libsodium/.libs/libsodium.a"
            let destinationPath = buildDir localBuildInfo <> "/libsodium.a"
            doesFileExist "cbits/libsodium-stable/Makefile"
              >>= \case
                    True ->
                      doesFileExist sourcePath
                        >>= \case
                              True -> moveArchive sourcePath destinationPath
                              False -> do
                                build
                                moveArchive sourcePath destinationPath
                    False -> do
                      configure
                      build
                      moveArchive sourcePath destinationPath
    }

moveArchive :: FilePath -> FilePath -> IO ()
moveArchive source destination = void . system $ "cp -v" <> source <> " " <> destination

configure :: IO ()
configure = void . system $ "cd cbits/libsodium-stable && ./configure"

build :: IO ()
build = void . system $ "cd cbits/libsodium-stable && make -j"

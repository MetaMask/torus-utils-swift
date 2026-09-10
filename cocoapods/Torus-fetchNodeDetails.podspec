Pod::Spec.new do |spec|
  spec.name = "Torus-fetchNodeDetails"
  # CocoaPods trunk still has 9.0.0 at the 8.0.1 commit. Point the TestApplication
  # at git tag 9.0.1 until a corrected pod is published.
  spec.version = "9.0.1"
  spec.ios.deployment_target = "13.0"
  spec.summary = "Fetches Torus node details"
  spec.homepage = "https://github.com/torusresearch/fetch-node-details-swift"
  spec.license = { :type => "BSD", :file => "License.md" }
  spec.swift_version = "5.3"
  spec.author = { "Torus Labs" => "hello@tor.us" }
  spec.source = {
    :git => "https://github.com/torusresearch/fetch-node-details-swift.git",
    :tag => spec.version
  }
  spec.source_files = "Sources/**/*.{swift,json}"
  spec.module_name = "FetchNodeDetails"
  spec.dependency "BigInt", "~> 5.2.0"
end

package gate

import (
	"errors"
	"fmt"
	"strings"
)

// resolveImage is the image to scan. It is used as is when set. Otherwise it is <image-repository>:<version>-<architecture>,
// the tags of the StreamingFast docker workflows: version is the tag name on a tag build, the first 7 characters of the commit
// otherwise, and the architecture the one of the runner.
func (g *Gate) resolveImage() (string, error) {
	image := g.Config.Image
	if image == "" {
		if g.Config.ImageRepository == "" {
			return "", errors.New("image-repository required when image is empty")
		}
		version := g.Config.SHA
		if len(version) > 7 {
			version = version[:7]
		}
		if tag, ok := strings.CutPrefix(g.Config.Ref, "refs/tags/"); ok {
			version = tag
		}

		var arch string
		switch g.Config.Arch {
		case "X64":
			arch = "amd64"
		case "ARM64":
			arch = "arm64"
		default:
			return "", fmt.Errorf("Unsupported runner architecture %s, set image", g.Config.Arch)
		}
		image = fmt.Sprintf("%s:%s-%s", g.Config.ImageRepository, version, arch)
	}

	g.Log.Printf("Image to scan: %s", image)
	return image, nil
}

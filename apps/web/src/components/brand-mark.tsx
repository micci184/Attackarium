import Image from "next/image";

const LOGO_WIDTH = 520;
const LOGO_HEIGHT = 96;

/**
 * Wordmark lockup. The light asset is dark ink for the default light chrome.
 * The dark asset is light ink and is shown only when the OS prefers a dark scheme.
 */
export function BrandMark() {
  return (
    <>
      <Image
        src="/brand/attackarium-logo-light.png"
        alt="Attackarium Threat Observatory"
        width={LOGO_WIDTH}
        height={LOGO_HEIGHT}
        priority
        className="h-8 w-auto dark:hidden"
        style={{ width: "auto", height: "2rem" }}
      />
      <Image
        src="/brand/attackarium-logo-dark.png"
        alt="Attackarium Threat Observatory"
        width={LOGO_WIDTH}
        height={LOGO_HEIGHT}
        priority
        className="hidden h-8 w-auto dark:block"
        style={{ width: "auto", height: "2rem" }}
      />
    </>
  );
}

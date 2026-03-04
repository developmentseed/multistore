import { defineConfig } from "vitepress";
import { withMermaid } from "vitepress-plugin-mermaid";

const adminSidebar = [
  {
    text: "Getting Started",
    items: [
      { text: "Quick Start", link: "/getting-started/" },
      {
        text: "Local Development",
        link: "/getting-started/local-development",
      },
    ],
  },
  {
    text: "Configuration",
    items: [
      { text: "Overview", link: "/configuration/" },
      { text: "Buckets", link: "/configuration/buckets" },
      { text: "Roles", link: "/configuration/roles" },
      { text: "Credentials", link: "/configuration/credentials" },
      {
        text: "Providers",
        collapsed: false,
        items: [
          { text: "Overview", link: "/configuration/providers/" },
          {
            text: "Static File",
            link: "/configuration/providers/static-file",
          },
          { text: "HTTP API", link: "/configuration/providers/http" },
          {
            text: "DynamoDB",
            link: "/configuration/providers/dynamodb",
          },
          {
            text: "PostgreSQL",
            link: "/configuration/providers/postgres",
          },
          {
            text: "Caching",
            link: "/configuration/providers/cached",
          },
        ],
      },
    ],
  },
  {
    text: "Authentication",
    items: [
      { text: "Overview", link: "/auth/" },
      {
        text: "Client Auth (OIDC/STS)",
        link: "/auth/proxy-auth",
      },
      {
        text: "Backend Auth",
        link: "/auth/backend-auth",
      },
      { text: "Sealed Session Tokens", link: "/auth/sealed-tokens" },
    ],
  },
  {
    text: "Deployment",
    items: [
      { text: "Overview", link: "/deployment/" },
      { text: "Server Runtime", link: "/deployment/server" },
      {
        text: "Cloudflare Workers",
        link: "/deployment/cloudflare-workers",
      },
    ],
  },
  {
    text: "Architecture",
    items: [
      { text: "Overview", link: "/architecture/" },
      { text: "Crate Layout", link: "/architecture/crate-layout" },
      {
        text: "Request Lifecycle",
        link: "/architecture/request-lifecycle",
      },
      {
        text: "Multi-Runtime Design",
        link: "/architecture/multi-runtime",
      },
    ],
  },
  {
    text: "Extending",
    items: [
      { text: "Overview", link: "/extending/" },
      { text: "Custom Resolver", link: "/extending/custom-resolver" },
      { text: "Custom Provider", link: "/extending/custom-provider" },
      { text: "Custom Backend", link: "/extending/custom-backend" },
    ],
  },
];

export default withMermaid(
  defineConfig({
    base: (process.env.VITEPRESS_BASE as `/${string}/` | undefined) ?? "/",
    title: "Multistore",
    description: "Multi-runtime S3 gateway proxy in Rust",

    themeConfig: {
      nav: [
        { text: "Getting Started", link: "/getting-started/" },
        { text: "Configuration", link: "/configuration/" },
        { text: "Reference", link: "/reference/" },
      ],

      sidebar: {
        "/getting-started/": adminSidebar,
        "/configuration/": adminSidebar,
        "/auth/": adminSidebar,
        "/deployment/": adminSidebar,
        "/architecture/": adminSidebar,
        "/extending/": adminSidebar,

        "/reference/": [
          {
            text: "Reference",
            items: [
              { text: "Overview", link: "/reference/" },
              {
                text: "Supported Operations",
                link: "/reference/operations",
              },
              { text: "Error Codes", link: "/reference/errors" },
              { text: "Config Example", link: "/reference/config-example" },
            ],
          },
        ],
      },

      socialLinks: [
        {
          icon: "github",
          link: "https://github.com/alukach/multistore",
        },
      ],

      search: {
        provider: "local",
      },
    },
  }),
);

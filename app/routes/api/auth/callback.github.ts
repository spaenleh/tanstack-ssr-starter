import { createAPIFileRoute } from "@tanstack/start/api";
import { OAuth2RequestError } from "arctic";
import { and, eq } from "drizzle-orm";
import { parseCookies } from "vinxi/http";
import {
  createSession,
  generateSessionToken,
  github,
  setSessionTokenCookie,
} from "~/server/auth";
import { db } from "~/server/db";
import { oauthAccount, user } from "~/server/db/schema";

interface GitHubUser {
  id: string;
  name: string | null;
  email: string | null;
  avatar_url: string;
  location: string | null;
  login: string;
}

interface GithubEmail {
  email: string;
  primary: boolean;
  verified: boolean;
  visibility: "public" | null;
}

export const APIRoute = createAPIFileRoute("/api/auth/callback/github")({
  GET: async ({ request }) => {
    const url = new URL(request.url);
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");

    const cookies = parseCookies();
    const storedState = cookies.github_oauth_state;

    if (!code || !state || !storedState || state !== storedState) {
      return new Response(null, {
        status: 400,
      });
    }

    const PROVIDER_ID = "github";

    try {
      const tokens = await github.validateAuthorizationCode(code);
      const githubUserResponse = await fetch("https://api.github.com/user", {
        headers: {
          Authorization: `Bearer ${tokens.accessToken()}`,
        },
      });
      let providerUser: GitHubUser = await githubUserResponse.json();

      const existingUser = await db.query.oauthAccount.findFirst({
        where: and(
          eq(oauthAccount.provider_id, PROVIDER_ID),
          eq(oauthAccount.provider_user_id, providerUser.id),
        ),
      });

      if (existingUser) {
        const token = generateSessionToken();
        const session = await createSession(token, existingUser.user_id);
        setSessionTokenCookie(token, session.expires_at);
        return new Response(null, {
          status: 302,
          headers: {
            Location: "/",
          },
        });
      } else {
        // email can be null if user did not allow email to be public
        if (providerUser.email == null) {
          const githubUserEmailResponse = await fetch(
            "https://api.github.com/user/emails",
            {
              headers: {
                Authorization: `Bearer ${tokens.accessToken()}`,
              },
            },
          );
          const providerUserEmails: [GithubEmail] = await githubUserEmailResponse.json();

          const primaryEmail = providerUserEmails.find((e) => e.primary == true)?.email;
          if (primaryEmail) {
            providerUser.email = primaryEmail;
          }
        }
        // TODO: do refactor code to not have to use non-null assertions
        const existingUserEmail = await db.query.user.findFirst({
          where: eq(user.email, providerUser.email!),
        });
        if (existingUserEmail) {
          await db.insert(oauthAccount).values({
            provider_id: PROVIDER_ID,
            provider_user_id: providerUser.id,
            user_id: existingUserEmail.id,
          });
          const token = generateSessionToken();
          const session = await createSession(token, existingUserEmail.id);
          setSessionTokenCookie(token, session.expires_at);
          return new Response(null, {
            status: 302,
            headers: {
              Location: "/",
            },
          });
        }
      }

      const userId = await db.transaction(async (tx) => {
        const [{ newId }] = await tx
          .insert(user)
          .values({
            // TODO: refactor code to not have to use non-null assertions
            email: providerUser.email!,
            name: providerUser.name || providerUser.login,
            avatar_url: providerUser.avatar_url,
          })
          .returning({ newId: user.id });
        await tx.insert(oauthAccount).values({
          provider_id: PROVIDER_ID,
          provider_user_id: providerUser.id,
          user_id: newId,
        });
        return newId;
      });

      const token = generateSessionToken();
      const session = await createSession(token, userId);
      setSessionTokenCookie(token, session.expires_at);
      return new Response(null, {
        status: 302,
        headers: {
          Location: "/",
        },
      });
    } catch (e) {
      console.log(e);
      if (e instanceof OAuth2RequestError) {
        return new Response(null, {
          status: 400,
        });
      }
      return new Response(null, {
        status: 500,
      });
    }
  },
});

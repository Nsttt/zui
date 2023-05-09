import crypto from "crypto";
import { type GetServerSidePropsContext } from "next";
import { env } from "@/env.mjs";
import { prisma } from "@/server/db";
import { PrismaAdapter } from "@next-auth/prisma-adapter";
import {
  getServerSession,
  type DefaultSession,
  type NextAuthOptions,
} from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";

import { UserSchema } from "./api/routers/auth";

/**
 * Module augmentation for `next-auth` types. Allows us to add custom properties to the `session`
 * object and keep type safety.
 *
 * @see https://next-auth.js.org/getting-started/typescript#module-augmentation
 */
declare module "next-auth" {
  interface Session extends DefaultSession {
    user: {
      id: string;
      // ...other properties
      // role: UserRole;
    } & DefaultSession["user"];
  }

  // interface User {
  //   // ...other properties
  //   // role: UserRole;
  // }
}

const getUser = async (username: string) => {
  const user = await prisma.user.findFirst({
    where: { username },
  });
  return user;
};

/**
 * Options for NextAuth.js used to configure adapters, providers, callbacks, etc.
 *
 * @see https://next-auth.js.org/configuration/options
 */
export const authOptions: NextAuthOptions = {
  secret: env.NEXTAUTH_SECRET,
  callbacks: {
    jwt: ({ token, user }) => {
      if (user) {
        token.id = user.id;
        token.email = user.email;
      }

      return token;
    },
    session: ({ session, user }) => ({
      ...session,
      user: {
        ...session.user,
        id: user.id,
      },
    }),
  },
  adapter: PrismaAdapter(prisma),
  providers: [
    CredentialsProvider({
      name: "Credentials",
      credentials: {
        email: {
          label: "Username",
          type: "text",
          placeholder: "Nsttt",
        },
        password: { label: "Password", type: "password" },
      },
      authorize: async (credentials) => {
        const cred = await UserSchema.parseAsync(credentials);

        const user = await getUser(cred.username);

        if (!user) {
          return null;
        }

        const isValidPassword =
          crypto
            .pbkdf2Sync(user.password, env.NEXTAUTH_SECRET, 1000, 64, `sha512`)
            .toString(`hex`) === cred.password;

        if (!isValidPassword) {
          return null;
        }

        return {
          id: user.id,
          username: user.username,
        };
      },
    }),
  ],
};

/**
 * Wrapper for `getServerSession` so that you don't need to import the `authOptions` in every file.
 * @see https://next-auth.js.org/configuration/nextjs
 */
export const getServerAuthSession = (ctx: {
  req: GetServerSidePropsContext["req"];
  res: GetServerSidePropsContext["res"];
}) => {
  return getServerSession(ctx.req, ctx.res, authOptions);
};

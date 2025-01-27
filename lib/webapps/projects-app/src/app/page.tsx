import { Button } from "@/components/Marketing/button";
import { Container } from "@/components/Marketing/container";
import { Footer } from "@/components/Marketing/footer";
import { Gradient } from "@/components/Marketing/gradient";
import { Navbar } from "@/components/Marketing/navbar";
import type { Metadata } from "next";

export const metadata: Metadata = {
  description:
    "Full-scale SaaS style web applications, developer APIs and custom software solutions.",
};

function Hero() {
  return (
    <div className="relative">
      <Gradient className="absolute inset-5 bottom-0 rounded-[45px] ring-1 ring-black/5 ring-inset" />
      <Container className="relative">
        <Navbar
        // banner={
        //   <Link
        //     href="/blog/radiant-raises-100m-series-a-from-tailwind-ventures"
        //     className="flex items-center gap-1 rounded-full bg-fuchsia-950/35 px-3 py-0.5 text-sm/6 font-medium text-white data-hover:bg-fuchsia-950/30"
        //   >
        //     Use code &quot;SPRING25&quot; for 3 months of free conversations
        //     <ChevronRight className="size-4" />
        //   </Link>
        // }
        />
        <div className="pt-16 pb-24 sm:pt-24 sm:pb-32 md:pt-32 md:pb-48">
          <h1 className="font-display text-6xl/[0.9] font-medium tracking-tight text-balance text-gray-950 sm:text-8xl/[0.8] md:text-9xl/[0.8]">
            Software by Matthew Bub
          </h1>
          <p className="mt-8 max-w-lg text-xl/7 font-medium text-gray-950/75 sm:text-2xl/8">
            Full-scale SaaS style web applications, developer APIs and custom
            software solutions with AI baked into the core.
          </p>
          <div className="mt-12 flex flex-col gap-x-6 gap-y-4 sm:flex-row">
            <Button href="#">Contact the Studio</Button>
            <Button variant="secondary" href="/pricing">
              Try the AI Chat
            </Button>
          </div>
        </div>
      </Container>
    </div>
  );
}

// export function FeatureSection() {
//   return (
//     <div className="overflow-hidden">
//       <Container className="pb-24">
//         <Heading as="h2" className="max-w-3xl">
//           A snapshot of your entire sales pipeline.
//         </Heading>
//         <Screenshot
//           width={1216}
//           height={768}
//           src="/screenshots/app.png"
//           className="mt-16 h-[36rem] sm:h-auto sm:w-[76rem]"
//         />
//       </Container>
//     </div>
//   );
// }

// export function BentoSection() {
//   return (
//     <Container>
//       <Subheading>Sales</Subheading>
//       <Heading as="h3" className="mt-2 max-w-3xl">
//         Know more about your customers than they do.
//       </Heading>

//       <div className="mt-10 grid grid-cols-1 gap-4 sm:mt-16 lg:grid-cols-6 lg:grid-rows-2">
//         <BentoCard
//           eyebrow="Insight"
//           title="Get perfect clarity"
//           description="Radiant uses social engineering to build a detailed financial picture of your leads. Know their budget, compensation package, social security number, and more."
//           graphic={
//             <div className="h-80 bg-[url(/screenshots/profile.png)] bg-[size:1000px_560px] bg-[left_-109px_top_-112px] bg-no-repeat" />
//           }
//           fade={["bottom"]}
//           className="max-lg:rounded-t-4xl lg:col-span-3 lg:rounded-tl-4xl"
//         />
//         <BentoCard
//           eyebrow="Analysis"
//           title="Undercut your competitors"
//           description="With our advanced data mining, you’ll know which companies your leads are talking to and exactly how much they’re being charged."
//           graphic={
//             <div className="absolute inset-0 bg-[url(/screenshots/competitors.png)] bg-[size:1100px_650px] bg-[left_-38px_top_-73px] bg-no-repeat" />
//           }
//           fade={["bottom"]}
//           className="lg:col-span-3 lg:rounded-tr-4xl"
//         />
//         <BentoCard
//           eyebrow="Speed"
//           title="Built for power users"
//           description="It’s never been faster to cold email your entire contact list using our streamlined keyboard shortcuts."
//           graphic={
//             <div className="flex size-full pt-10 pl-10">
//               <Keyboard highlighted={["LeftCommand", "LeftShift", "D"]} />
//             </div>
//           }
//           className="lg:col-span-2 lg:rounded-bl-4xl"
//         />
//         <BentoCard
//           eyebrow="Source"
//           title="Get the furthest reach"
//           description="Bypass those inconvenient privacy laws to source leads from the most unexpected places."
//           graphic={<LogoCluster />}
//           className="lg:col-span-2"
//         />
//         <BentoCard
//           eyebrow="Limitless"
//           title="Sell globally"
//           description="Radiant helps you sell in locations currently under international embargo."
//           graphic={<Map />}
//           className="max-lg:rounded-b-4xl lg:col-span-2 lg:rounded-br-4xl"
//         />
//       </div>
//     </Container>
//   );
// }

// export function DarkBentoSection() {
//   return (
//     <div className="mx-2 mt-2 rounded-4xl bg-gray-900 py-32">
//       <Container>
//         <Subheading dark>Outreach</Subheading>
//         <Heading as="h3" dark className="mt-2 max-w-3xl">
//           Customer outreach has never been easier.
//         </Heading>

//         <div className="mt-10 grid grid-cols-1 gap-4 sm:mt-16 lg:grid-cols-6 lg:grid-rows-2">
//           <BentoCard
//             dark
//             eyebrow="Networking"
//             title="Sell at the speed of light"
//             description="Our RadiantAI chat assistants analyze the sentiment of your conversations in real time, ensuring you're always one step ahead."
//             graphic={
//               <div className="h-80 bg-[url(/screenshots/networking.png)] bg-[size:851px_344px] bg-no-repeat" />
//             }
//             fade={["top"]}
//             className="max-lg:rounded-t-4xl lg:col-span-4 lg:rounded-tl-4xl"
//           />
//           <BentoCard
//             dark
//             eyebrow="Integrations"
//             title="Meet leads where they are"
//             description="With thousands of integrations, no one will be able to escape your cold outreach."
//             graphic={<LogoTimeline />}
//             // `overflow-visible!` is needed to work around a Chrome bug that disables the mask on the graphic.
//             className="z-10 overflow-visible! lg:col-span-2 lg:rounded-tr-4xl"
//           />
//           <BentoCard
//             dark
//             eyebrow="Meetings"
//             title="Smart call scheduling"
//             description="Automatically insert intro calls into your leads' calendars without their consent."
//             graphic={<LinkedAvatars />}
//             className="lg:col-span-2 lg:rounded-bl-4xl"
//           />
//           <BentoCard
//             dark
//             eyebrow="Engagement"
//             title="Become a thought leader"
//             description="RadiantAI automatically writes LinkedIn posts that relate current events to B2B sales, helping you build a reputation as a thought leader."
//             graphic={
//               <div className="h-80 bg-[url(/screenshots/engagement.png)] bg-[size:851px_344px] bg-no-repeat" />
//             }
//             fade={["top"]}
//             className="max-lg:rounded-b-4xl lg:col-span-4 lg:rounded-br-4xl"
//           />
//         </div>
//       </Container>
//     </div>
//   );
// }

export default function Home() {
  return (
    <div className="overflow-hidden">
      <Hero />
      <main>
        {/* <Container className="mt-10">
          <LogoCloud />
        </Container> */}
        {/* <div className="bg-linear-to-b from-white from-50% to-gray-100 py-32"> */}
        {/* <FeatureSection /> */}
        {/* <BentoSection /> */}
        {/* </div> */}
        {/* <DarkBentoSection /> */}
      </main>
      {/* <Testimonials /> */}
      <Footer />
    </div>
  );
}

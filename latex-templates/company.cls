% Company Report LaTeX Class
% For use with Pandoc to generate branded PDF reports
% Based on article class with company branding

\NeedsTeXFormat{LaTeX2e}
\ProvidesClass{company}[2025/10/30 Company Report Class]

% Load base class
\LoadClass[11pt,letterpaper]{article}

% Required packages
\RequirePackage{ifxetex,ifluatex}
\newif\ifxetexorluatex
\ifxetex
  \xetexorluatextrue
\else
  \ifluatex
    \xetexorluatextrue
  \else
    \xetexorluatexfalse
  \fi
\fi

\ifxetexorluatex
  \RequirePackage{fontspec}
  \defaultfontfeatures{Ligatures=TeX,Scale=MatchLowercase}
\else
  \RequirePackage[utf8]{inputenc}
  \RequirePackage[T1]{fontenc}
\fi

\RequirePackage{geometry}
\RequirePackage{graphicx}
\RequirePackage{xcolor}
\RequirePackage{fancyhdr}
\RequirePackage{titlesec}
\RequirePackage{hyperref}
\RequirePackage{enumitem}
\RequirePackage{tocloft}
\RequirePackage{lastpage}

% Packages for proper verbatim handling with line breaking
\RequirePackage{fancyvrb}
\RequirePackage{listings}

% Configure listings for automatic line breaking
\lstset{
  basicstyle=\ttfamily\footnotesize,
  breaklines=true,
  breakatwhitespace=true,
  breakindent=0pt,
  breakautoindent=true,
  columns=flexible,
  keepspaces=true,
  showstringspaces=false,
  frame=single,
  framesep=3pt,
  xleftmargin=3pt,
  xrightmargin=3pt,
  backgroundcolor=\color{CodeBackground}
}

% Define colors for code blocks
\definecolor{CodeBackground}{RGB}{248,248,248}
\definecolor{CodeBorder}{RGB}{221,221,221}

% Font packages - using sans-serif for clean, modern appearance
\ifxetexorluatex
  % Use system fonts for modern engines
  \setmainfont{DejaVu Sans}[
    UprightFont = *,
    BoldFont = * Bold,
    ItalicFont = * Oblique,
    BoldItalicFont = * Bold Oblique
  ]
\else
  % Use Type 1 fonts for pdflatex
  \RequirePackage{helvet}
  \renewcommand{\familydefault}{\sfdefault}

  % Load newunicodechar and set up emoji substitutions
  \RequirePackage{newunicodechar}

  % Unicode character substitutions for pdflatex
  % Common emoji and special characters
  \DeclareUnicodeCharacter{2705}{[OK]}      % ✅
  \DeclareUnicodeCharacter{274C}{[X]}       % ❌
  \DeclareUnicodeCharacter{26A0}{[!]}       % ⚠
  \DeclareUnicodeCharacter{2713}{[+]}       % ✓
  \DeclareUnicodeCharacter{2717}{[-]}       % ✗
  \DeclareUnicodeCharacter{25B6}{>}         % ▶
  \DeclareUnicodeCharacter{25C0}{<}         % ◀
  \DeclareUnicodeCharacter{25CF}{*}         % ●
  \DeclareUnicodeCharacter{25CB}{o}         % ○
  \DeclareUnicodeCharacter{2192}{->}        % →
  \DeclareUnicodeCharacter{2190}{<-}        % ←
  \DeclareUnicodeCharacter{2194}{<->}       % ↔
  \DeclareUnicodeCharacter{21D2}{=>}        % ⇒
  \DeclareUnicodeCharacter{21D0}{<=}        % ⇐
  \DeclareUnicodeCharacter{21D4}{<=>}       % ⇔
  \DeclareUnicodeCharacter{2026}{...}       % …
  \DeclareUnicodeCharacter{2013}{--}        % –
  \DeclareUnicodeCharacter{2014}{---}       % —
  \DeclareUnicodeCharacter{2033}{''}        % ″
  \DeclareUnicodeCharacter{2032}{'}         % ′
  \DeclareUnicodeCharacter{00B0}{deg}       % °
  \DeclareUnicodeCharacter{00B1}{+/-}       % ±
  \DeclareUnicodeCharacter{00D7}{x}         % ×
  \DeclareUnicodeCharacter{00F7}{/}         % ÷
  \DeclareUnicodeCharacter{2248}{~}         % ≈
  \DeclareUnicodeCharacter{2260}{!=}        % ≠
  \DeclareUnicodeCharacter{2264}{<=}        % ≤
  \DeclareUnicodeCharacter{2265}{>=}        % ≥
  \DeclareUnicodeCharacter{1F512}{[LOCK]}   % 🔒
  \DeclareUnicodeCharacter{1F513}{[UNLOCK]} % 🔓
  \DeclareUnicodeCharacter{1F511}{[KEY]}    % 🔑
  \DeclareUnicodeCharacter{26A1}{[BOLT]}    % ⚡
  \DeclareUnicodeCharacter{1F680}{[ROCKET]} % 🚀
  \DeclareUnicodeCharacter{1F4CA}{[CHART]}  % 📊
  \DeclareUnicodeCharacter{1F4C8}{[UP]}     % 📈
  \DeclareUnicodeCharacter{1F4C9}{[DOWN]}   % 📉
  \DeclareUnicodeCharacter{1F4A1}{[IDEA]}   % 💡
  \DeclareUnicodeCharacter{1F50D}{[SEARCH]} % 🔍
  \DeclareUnicodeCharacter{1F916}{[ROBOT]}  % 🤖
\fi

% Page geometry - professional margins
\geometry{
    top=1in,
    bottom=1in,
    left=1in,
    right=1in,
    headheight=14pt,
    headsep=0.25in,
    footskip=0.5in
}

% Company color palette - black and white only
\definecolor{CompanyPrimary}{RGB}{0,0,0}           % Black - primary text
\definecolor{CompanyAccent}{RGB}{0,0,0}            % Black - accents (no color)
\definecolor{CompanyLight}{RGB}{245,245,245}       % Light background
\definecolor{CompanyDark}{RGB}{51,51,51}           % Dark gray for secondary text
\definecolor{CompanyLink}{RGB}{0,0,0}              % Black - links (no color)

% Hyperlink setup
\hypersetup{
    colorlinks=true,
    linkcolor=CompanyPrimary,
    urlcolor=CompanyLink,
    citecolor=CompanyPrimary,
    pdfborder={0 0 0},
    pdftitle={Company Report},
    pdfauthor={Company}
}

% Header and footer setup
\pagestyle{fancy}
\fancyhf{}
\renewcommand{\headrulewidth}{0.5pt}
\renewcommand{\footrulewidth}{0.5pt}
\fancyhead[L]{\textcolor{CompanyPrimary}{\sffamily\small\ifdef{\@companyname}{\@companyname}{Company}}}
\fancyhead[R]{\textcolor{CompanyPrimary}{\sffamily\small\@title}}
\fancyfoot[L]{\textcolor{CompanyDark}{\sffamily\small \ifdef{\@companyname}{\@companyname}{Company}}}
\fancyfoot[C]{\textcolor{CompanyDark}{\sffamily\small\@date}}
\fancyfoot[R]{\textcolor{CompanyDark}{\sffamily\small Page \thepage\ of \pageref{LastPage}}}

% Title page style
\fancypagestyle{plain}{%
    \fancyhf{}
    \renewcommand{\headrulewidth}{0pt}
    \renewcommand{\footrulewidth}{0.5pt}
    \fancyfoot[L]{\textcolor{CompanyDark}{\sffamily\small \ifdef{\@companyname}{\@companyname}{Company}}}
    \fancyfoot[C]{\textcolor{CompanyDark}{\sffamily\small\@date}}
    \fancyfoot[R]{\textcolor{CompanyDark}{\sffamily\small Page \thepage\ of \pageref{LastPage}}}
}

% Section formatting - clean, geometric style
\titleformat{\section}
    {\Large\sffamily\bfseries\color{CompanyPrimary}}
    {\thesection}{1em}{}
    [\vspace{2pt}\color{CompanyAccent}\titlerule]

\titleformat{\subsection}
    {\large\sffamily\bfseries\color{CompanyPrimary}}
    {\thesubsection}{1em}{}

\titleformat{\subsubsection}
    {\normalsize\sffamily\bfseries\color{CompanyPrimary}}
    {\thesubsubsection}{1em}{}

% Spacing adjustments
\titlespacing*{\section}{0pt}{12pt}{6pt}
\titlespacing*{\subsection}{0pt}{10pt}{4pt}
\titlespacing*{\subsubsection}{0pt}{8pt}{3pt}

% List formatting - clean and minimal
\setlist{nosep, leftmargin=*, itemsep=3pt}
\setlist[itemize,1]{label=\textcolor{CompanyAccent}{\textbullet}}
\setlist[itemize,2]{label=\textcolor{CompanyDark}{\textendash}}

% Table of contents formatting
\renewcommand{\cftsecfont}{\sffamily\bfseries\color{CompanyPrimary}}
\renewcommand{\cftsubsecfont}{\sffamily\color{CompanyPrimary}}
\renewcommand{\cftsecpagefont}{\sffamily\color{CompanyPrimary}}
\renewcommand{\cftsubsecpagefont}{\sffamily\color{CompanyDark}}

% Custom title page
\renewcommand{\maketitle}{%
    \begin{titlepage}
        \centering
        \vspace*{2cm}

        % Company logo/wordmark (uses \@companyname if defined, otherwise "COMPANY")
        \ifdef{\@companyname}{%
            {\Huge\sffamily\bfseries\color{CompanyPrimary} \MakeUppercase{\@companyname}\par}
        }{%
            {\Huge\sffamily\bfseries\color{CompanyPrimary} COMPANY\par}
        }
        \vspace{0.5cm}
        {\color{CompanyAccent}\rule{0.5\textwidth}{2pt}\par}

        \vspace{2cm}

        % Document title
        {\huge\sffamily\bfseries\color{CompanyPrimary}\@title\par}

        \vspace{1cm}

        % Subtitle if provided
        \ifdef{\@subtitle}{%
            {\Large\sffamily\color{CompanyDark}\@subtitle\par}
            \vspace{0.5cm}
        }{}

        % Author
        \ifdef{\@author}{%
            {\large\sffamily\color{CompanyPrimary}\@author\par}
        }{}

        \vfill

        % Date
        {\large\sffamily\color{CompanyDark}\@date\par}

        \vspace{1cm}
    \end{titlepage}
}

% Subtitle command
\newcommand{\subtitle}[1]{\def\@subtitle{#1}}

% Company name command (for customization)
\newcommand{\companyname}[1]{\def\@companyname{#1}}

% Abstract environment customization
\renewenvironment{abstract}{%
    \section*{Executive Summary}
    \color{CompanyDark}
}{%
    \vspace{1em}
}

% Code block styling (for Pandoc)
\definecolor{CodeBackground}{RGB}{248,248,248}
\definecolor{CodeBorder}{RGB}{221,221,221}

% Quote environment
\renewenvironment{quote}{%
    \list{}{%
        \leftmargin=1cm
        \rightmargin=1cm
    }%
    \item\relax
    \color{CompanyDark}
    \itshape
}{%
    \endlist
}

% Pandoc compatibility - ensure proper handling of special elements
\providecommand{\tightlist}{%
    \setlength{\itemsep}{0pt}\setlength{\parskip}{0pt}
}

% Document metadata commands for Pandoc
\providecommand{\classification}[1]{\def\@classification{#1}}
\providecommand{\version}[1]{\def\@version{#1}}
\providecommand{\status}[1]{\def\@status{#1}}

% Optional header additions for classified/versioned documents
\newcommand{\addmetaheader}{%
    \fancyhead[L]{\textcolor{CompanyPrimary}{\sffamily\small
        \ifdef{\@classification}{\@classification\ $\cdot$ }{}%
        \ifdef{\@version}{v\@version}{}%
    }}
}

\endinput

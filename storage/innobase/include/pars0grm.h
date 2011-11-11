
/* A Bison parser, made by GNU Bison 2.4.1.  */

/* Skeleton interface for Bison's Yacc-like parsers in C
   
      Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004, 2005, 2006
   Free Software Foundation, Inc.
   
   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.
   
   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */


/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     PARS_INT_LIT = 258,
     PARS_FLOAT_LIT = 259,
     PARS_STR_LIT = 260,
     PARS_FIXBINARY_LIT = 261,
     PARS_BLOB_LIT = 262,
     PARS_NULL_LIT = 263,
     PARS_ID_TOKEN = 264,
     PARS_AND_TOKEN = 265,
     PARS_OR_TOKEN = 266,
     PARS_NOT_TOKEN = 267,
     PARS_GE_TOKEN = 268,
     PARS_LE_TOKEN = 269,
     PARS_NE_TOKEN = 270,
     PARS_PROCEDURE_TOKEN = 271,
     PARS_IN_TOKEN = 272,
     PARS_OUT_TOKEN = 273,
     PARS_BINARY_TOKEN = 274,
     PARS_BLOB_TOKEN = 275,
     PARS_INT_TOKEN = 276,
     PARS_INTEGER_TOKEN = 277,
     PARS_FLOAT_TOKEN = 278,
     PARS_CHAR_TOKEN = 279,
     PARS_IS_TOKEN = 280,
     PARS_BEGIN_TOKEN = 281,
     PARS_END_TOKEN = 282,
     PARS_IF_TOKEN = 283,
     PARS_THEN_TOKEN = 284,
     PARS_ELSE_TOKEN = 285,
     PARS_ELSIF_TOKEN = 286,
     PARS_LOOP_TOKEN = 287,
     PARS_WHILE_TOKEN = 288,
     PARS_RETURN_TOKEN = 289,
     PARS_SELECT_TOKEN = 290,
     PARS_SUM_TOKEN = 291,
     PARS_COUNT_TOKEN = 292,
     PARS_DISTINCT_TOKEN = 293,
     PARS_FROM_TOKEN = 294,
     PARS_WHERE_TOKEN = 295,
     PARS_FOR_TOKEN = 296,
     PARS_DDOT_TOKEN = 297,
     PARS_READ_TOKEN = 298,
     PARS_ORDER_TOKEN = 299,
     PARS_BY_TOKEN = 300,
     PARS_ASC_TOKEN = 301,
     PARS_DESC_TOKEN = 302,
     PARS_INSERT_TOKEN = 303,
     PARS_INTO_TOKEN = 304,
     PARS_VALUES_TOKEN = 305,
     PARS_UPDATE_TOKEN = 306,
     PARS_SET_TOKEN = 307,
     PARS_DELETE_TOKEN = 308,
     PARS_CURRENT_TOKEN = 309,
     PARS_OF_TOKEN = 310,
     PARS_CREATE_TOKEN = 311,
     PARS_TABLE_TOKEN = 312,
     PARS_INDEX_TOKEN = 313,
     PARS_UNIQUE_TOKEN = 314,
     PARS_CLUSTERED_TOKEN = 315,
     PARS_DOES_NOT_FIT_IN_MEM_TOKEN = 316,
     PARS_ON_TOKEN = 317,
     PARS_ASSIGN_TOKEN = 318,
     PARS_DECLARE_TOKEN = 319,
     PARS_CURSOR_TOKEN = 320,
     PARS_SQL_TOKEN = 321,
     PARS_OPEN_TOKEN = 322,
     PARS_FETCH_TOKEN = 323,
     PARS_CLOSE_TOKEN = 324,
     PARS_NOTFOUND_TOKEN = 325,
     PARS_TO_CHAR_TOKEN = 326,
     PARS_TO_NUMBER_TOKEN = 327,
     PARS_TO_BINARY_TOKEN = 328,
     PARS_BINARY_TO_NUMBER_TOKEN = 329,
     PARS_SUBSTR_TOKEN = 330,
     PARS_REPLSTR_TOKEN = 331,
     PARS_CONCAT_TOKEN = 332,
     PARS_INSTR_TOKEN = 333,
     PARS_LENGTH_TOKEN = 334,
     PARS_SYSDATE_TOKEN = 335,
     PARS_PRINTF_TOKEN = 336,
     PARS_ASSERT_TOKEN = 337,
     PARS_RND_TOKEN = 338,
     PARS_RND_STR_TOKEN = 339,
     PARS_ROW_PRINTF_TOKEN = 340,
     PARS_COMMIT_TOKEN = 341,
     PARS_ROLLBACK_TOKEN = 342,
     PARS_WORK_TOKEN = 343,
     PARS_UNSIGNED_TOKEN = 344,
     PARS_EXIT_TOKEN = 345,
     PARS_FUNCTION_TOKEN = 346,
     PARS_LOCK_TOKEN = 347,
     PARS_SHARE_TOKEN = 348,
     PARS_MODE_TOKEN = 349,
     PARS_LIKE_TOKEN = 350,
     PARS_LIKE_TOKEN_EXACT = 351,
     PARS_LIKE_TOKEN_PREFIX = 352,
     PARS_LIKE_TOKEN_SUFFIX = 353,
     PARS_LIKE_TOKEN_SUBSTR = 354,
     PARS_TABLE_NAME_TOKEN = 355,
     PARS_COMPACT_TOKEN = 356,
     PARS_BLOCK_SIZE_TOKEN = 357,
     PARS_BIGINT_TOKEN = 358,
     NEG = 359
   };
#endif



#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef int YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
#endif

extern YYSTYPE yylval;



{
    switch calldataload(0)
    case 0x01000000000000000000000000000000000000010 { sstore(0, 1) }
    case 0x02000000000000000000000000000000000000010 { sstore(1, 1) }
    case 0x01000000000000000000000000000000000000020 { sstore(2, 1) }
    case 0x02000000000000000000000000000000000000020 { sstore(3, 1) }
    default { sstore(8, 9) }
}
// ====
// step: wordSizeTransform
// ----
// {
//     let _1_0 := 0
//     let _1_1 := 0
//     let _1_2 := 0
//     let _1_3 := 0
//     let _2_0, _2_1, _2_2, _2_3 := calldataload(_1_0, _1_1, _1_2, _1_3)
//     let run_default
//     switch _2_0
//     case 0 {
//         switch _2_1
//         case 268435456 {
//             switch _2_2
//             case 0 {
//                 switch _2_3
//                 case 16 {
//                     let _3_0 := 0
//                     let _3_1 := 0
//                     let _3_2 := 0
//                     let _3_3 := 1
//                     let _4_0 := 0
//                     let _4_1 := 0
//                     let _4_2 := 0
//                     let _4_3 := 0
//                     sstore(_4_0, _4_1, _4_2, _4_3, _3_0, _3_1, _3_2, _3_3)
//                 }
//                 case 32 {
//                     let _7_0 := 0
//                     let _7_1 := 0
//                     let _7_2 := 0
//                     let _7_3 := 1
//                     let _8_0 := 0
//                     let _8_1 := 0
//                     let _8_2 := 0
//                     let _8_3 := 2
//                     sstore(_8_0, _8_1, _8_2, _8_3, _7_0, _7_1, _7_2, _7_3)
//                 }
//                 default { run_default := 1 }
//             }
//             default { run_default := 1 }
//         }
//         case 536870912 {
//             switch _2_2
//             case 0 {
//                 switch _2_3
//                 case 16 {
//                     let _5_0 := 0
//                     let _5_1 := 0
//                     let _5_2 := 0
//                     let _5_3 := 1
//                     let _6_0 := 0
//                     let _6_1 := 0
//                     let _6_2 := 0
//                     let _6_3 := 1
//                     sstore(_6_0, _6_1, _6_2, _6_3, _5_0, _5_1, _5_2, _5_3)
//                 }
//                 case 32 {
//                     let _9_0 := 0
//                     let _9_1 := 0
//                     let _9_2 := 0
//                     let _9_3 := 1
//                     let _10_0 := 0
//                     let _10_1 := 0
//                     let _10_2 := 0
//                     let _10_3 := 3
//                     sstore(_10_0, _10_1, _10_2, _10_3, _9_0, _9_1, _9_2, _9_3)
//                 }
//                 default { run_default := 1 }
//             }
//             default { run_default := 1 }
//         }
//         default { run_default := 1 }
//     }
//     default { run_default := 1 }
//     if run_default
//     {
//         let _11_0 := 0
//         let _11_1 := 0
//         let _11_2 := 0
//         let _11_3 := 9
//         let _12_0 := 0
//         let _12_1 := 0
//         let _12_2 := 0
//         let _12_3 := 8
//         sstore(_12_0, _12_1, _12_2, _12_3, _11_0, _11_1, _11_2, _11_3)
//     }
// }
